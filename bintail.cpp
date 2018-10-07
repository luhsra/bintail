#include <iostream>
#include <string>
#include <set>
#include <iomanip>
#include <memory>
#include <err.h>
#include <stdio.h>
#include <cstdlib>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <regex>

#include "bintail.h"
#include "mvelem.h"

using namespace std;

static uint64_t sym_value(vector<struct symbol> &syms, const char* name) {
    auto it =find_if(syms.cbegin(), syms.cend(), [name](auto& s) {
            return s.name == name;
            });
    if (it == syms.cend())
        throw std::runtime_error("Symbol not found");
    return it->sym.st_value;
}

static std::optional<Elf_Scn*> get_scn(vector<struct sec> &secs, const char* name) {
    auto it = find_if(secs.cbegin(), secs.cend(), [name](auto& s) {
            return s.name == name;
            });
    if (it == secs.cend())
        return {};
    else 
        return it->scn;
}

Bintail::~Bintail() {
    elf_end(e_out);
    close(outfd);
    elf_end(e_in);
    close(infd);
}

Bintail::Bintail(const char *infile) {
    /* init libelf state */ 
    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(1, "libelf init failed");
    if ((infd = open(infile, O_RDONLY)) == -1) 
        errx(1, "open %s failed. %s", infile, strerror(errno));
    if ((e_in = elf_begin(infd, ELF_C_READ, NULL)) == nullptr)
        errx(1, "elf_begin infile failed.");

    /* Read sections */
    Elf_Scn *scn = nullptr;
    GElf_Shdr shdr;
    size_t shstrndx;
    elf_getshdrstrndx(e_in, &shstrndx);
    while((scn = elf_nextscn(e_in, scn)) != nullptr) {
        struct sec s;
        gelf_getshdr(scn, &shdr);
        s.scn = scn;
        s.shdr = shdr;
        s.name = elf_strptr(e_in, shstrndx, shdr.sh_name);
        secs.push_back(s);
    }

    // ToDo(Felix): Multiple reloc sections
    for (const auto& sec : secs)
        if (sec.shdr.sh_type == SHT_RELA && sec.shdr.sh_info == 0)
            reloc_scn = sec.scn;

    symtab_scn = get_scn(secs, ".symtab").value();
    if (symtab_scn == nullptr)
        throw std::runtime_error("Need symtab for multiverse boundries.");

    /* Must exist */
    Elf_Scn *rodata_scn = get_scn(secs, ".rodata").value();
    Elf_Scn *data_scn = get_scn(secs, ".data").value();
    Elf_Scn *text_scn = get_scn(secs, ".text").value();
    Elf_Scn *dynamic_scn = get_scn(secs, ".dynamic").value();
    Elf_Scn *bss_scn = get_scn(secs, ".bss").value();
    Elf_Scn *mvvar_scn = get_scn(secs, "__multiverse_var_").value();
    rodata.load (e_in, rodata_scn);
    data.load   (e_in, data_scn);
    text.load   (e_in, text_scn);
    dynamic.load(e_in, dynamic_scn);
    bss.load    (e_in, bss_scn);
    mvvar.load  (e_in, mvvar_scn);
    if (mvvar.max_sz() == 0) {
        cerr << "Executable has no multiverse variables.\n";
        exit(0);
    }

    /* Must have internal consistency */
    mvfn.load   (e_in, get_scn(secs, "__multiverse_fn_").value_or(nullptr));
    mvcs.load   (e_in, get_scn(secs, "__multiverse_callsite_").value_or(nullptr));
    mvdata.load (e_in, get_scn(secs, "__multiverse_data_").value_or(nullptr));
    mvtext.load (e_in, get_scn(secs, "__multiverse_text_").value_or(nullptr));

    /* read info sections */
    auto mvvar_infos = mvvar.read();
    auto mvcs_infos = mvcs.read();
    auto mvfn_infos = mvfn.read();
    for (auto e : *mvvar_infos)
        vars.push_back(make_unique<MVVar>(e, &rodata, &data));
    for (auto e : *mvcs_infos)
        pps.push_back(make_unique<MVPP>(e, &text, &mvtext));
    for (auto e : *mvfn_infos) {
        auto f = make_unique<MVFn>(e, &mvdata, &mvtext, &rodata);
        auto pp = make_unique<MVPP>(f.get());
        f->add_pp(pp.get());
        fns.push_back(move(f));
        pps.push_back(move(pp));
    }

    /* multiverse_init equivalent */
    // find var & save ptr to it
    //    add fn to var.functions_head
    for (auto& fn : fns)
        for (auto& var: vars)
            fn->probe_var(var.get());

    // 1. Find function
    // 2. Create patchpoint
    // 3. Append pp to fn ll
    for (auto& pp : pps)
        for (auto& fn : fns) {
            if (fn->location() != pp->function_body )
                continue;
            fn->add_pp(pp.get());
            pp->set_fn(fn.get());
        }

    /* Keep symbols the same (refs to index) */
    GElf_Sym sym;
    Elf_Data * d2 = elf_getdata(symtab_scn, nullptr);
    gelf_getshdr(symtab_scn, &shdr);
    for (size_t i=0; i < d2->d_size / shdr.sh_entsize; i++) {
        gelf_getsym(d2, i, &sym);
        struct symbol s;
        s.sym = sym;
        s.name = elf_strptr(e_in, shdr.sh_link, sym.st_name);
        syms.push_back(s);
    }
    mvvar.start_ptr = sym_value(syms, "__start___multiverse_var_ptr");
    mvvar.stop_ptr  = sym_value(syms, "__stop___multiverse_var_ptr");
    mvfn.start_ptr  = sym_value(syms, "__start___multiverse_fn_ptr");
    mvfn.stop_ptr   = sym_value(syms, "__stop___multiverse_fn_ptr");
    mvcs.start_ptr  = sym_value(syms, "__start___multiverse_callsite_ptr");
    mvcs.stop_ptr   = sym_value(syms, "__stop___multiverse_callsite_ptr");

    for (auto& sym : syms)
        for (auto& fn : fns)
            fn->probe_sym(sym);

    // Remove claimed relocs (Regenerate on trim)
    GElf_Rela rela;
    gelf_getshdr(reloc_scn, &shdr);
    auto d = elf_getdata(reloc_scn, nullptr);
    for (size_t i=0; i < d->d_size / shdr.sh_entsize; i++) {
        gelf_getrela(d, i, &rela);
        auto claims = 0u;
        claims += mvvar.probe_rela(&rela);
        claims += mvfn.probe_rela(&rela);
        claims += mvcs.probe_rela(&rela);
        claims += mvdata.probe_rela(&rela);
        if (claims == 0)
            rela_other.push_back(rela);
    }
}

void Bintail::change(string change_str) {
    smatch m;
    regex_search(change_str, m, regex(R"((\w+)=(\d+))"));
    auto var_name = m.str(1);
    auto value = stoi(m.str(2));
    for (auto& e : vars)
        if (var_name == e->name())
            e->set_value(value, &data);
}

/**
 * Remove variance
 *  guard - replace mvtext entry of unused with 0xc3
 */
void Bintail::apply(string change_str, bool guard) {
    smatch m;
    regex_search(change_str, m, regex(R"((\w+))"));
    auto var_name = m.str(1);
    for (auto& e : vars)
        if (var_name == e->name())
            e->apply(&text, &mvtext, guard);
}

void Bintail::apply_all(bool guard) {
    for (auto& e : vars)
        e->apply(&text, &mvtext, guard);
}

/**
 * Regenerate rela & sym table & update .dynamic info
 */
void Bintail::update_relocs_sym() {
    vector<GElf_Rela>* rvv[] = { 
        &data.relocs,
        &mvvar.relocs,
        &mvdata.relocs,
        &mvfn.relocs,
        &mvcs.relocs, 
        &mvtext.relocs,
        &rela_other
    };

    GElf_Shdr shdr, sym_shdr;
    gelf_getshdr(reloc_scn, &shdr);
    gelf_getshdr(symtab_scn, &sym_shdr);
    auto d = elf_getdata(reloc_scn, nullptr);
    auto d2 = elf_getdata(symtab_scn, nullptr);

    // RELOCS
    int i = 0;
    int cnt = 0;
    for (auto v : rvv) 
        for (auto r : *v) {
            if (r.r_info == R_X86_64_RELATIVE)
                cnt++;
            if (!gelf_update_rela (d, i++, &r))
                cout << "Error: gelf_update_rela() "
                    << elf_errmsg(elf_errno()) << endl;
        }

    assert(sizeof(GElf_Rela) == shdr.sh_entsize);
    shdr.sh_size = i * sizeof(GElf_Rela);
    d->d_size = shdr.sh_size;

    auto dyn_relacount = dynamic.get_dyn(DT_RELACOUNT);
    auto dyn_relasz = dynamic.get_dyn(DT_RELASZ);
    dyn_relacount->d_un.d_val = cnt;
    dyn_relasz->d_un.d_val = shdr.sh_size;

    // SYMS
    i = 0;
    for (auto s : syms) {
        if (!gelf_update_sym(d2, i++, &s.sym))
            cout << "Error: gelf_update_sym() "
                << elf_errmsg(elf_errno()) << endl;
    }

    assert(sizeof(GElf_Sym) == sym_shdr.sh_entsize);
    sym_shdr.sh_size = i * sizeof(GElf_Sym);
    d2->d_size = sym_shdr.sh_size;

    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
    elf_flagdata(d2, ELF_C_SET, ELF_F_DIRTY);
    gelf_update_shdr(reloc_scn, &shdr);
    gelf_update_shdr(symtab_scn, &sym_shdr);
    elf_flagshdr(reloc_scn, ELF_C_SET, ELF_F_DIRTY);
    elf_flagshdr(symtab_scn, ELF_C_SET, ELF_F_DIRTY);
}

void Bintail::write(const char *outfile) {
    if ((outfd = open(outfile, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IXUSR)) == -1) 
        errx(1, "open %s failed. %s", outfile, strerror(errno));
    if ((e_out = elf_begin(outfd, ELF_C_WRITE, NULL)) == nullptr)
        errx(1, "elf_begin outfile failed.");

     // Manual layout: Sections in segments have to be relocated manualy
    elf_flagelf(e_out, ELF_C_SET, ELF_F_LAYOUT);
    gelf_newehdr(e_out, ELFCLASS64);

    /* MV Areas */
    Area mvinfo_area{e_out};
    mvinfo_area.add_section(&mvvar);
    mvinfo_area.add_section(&mvfn);
    mvinfo_area.add_section(&mvdata);
    mvinfo_area.add_section(&mvcs);
    mvinfo_area.add_section(&bss);
    Area mvtext_area{e_out};
    mvtext_area.add_section(&mvtext);

    /* Copy & find area segments */
    size_t phdr_num;
    GElf_Phdr in_phdr, out_phdr;
    elf_getphdrnum(e_in, &phdr_num);
    gelf_newphdr(e_out, phdr_num);
    for (auto i=0u; i<phdr_num; i++) {
        gelf_getphdr(e_in, i, &in_phdr);
        gelf_getphdr(e_out, i, &out_phdr);
        out_phdr = in_phdr; // 1:1 adjust for area later
        gelf_update_phdr(e_out, i, &out_phdr);
        if (in_phdr.p_type != PT_LOAD)
            continue;
        if (mvinfo_area.test_phdr(in_phdr))
            mvinfo_area.set_phdr(in_phdr, i);
        if (mvtext_area.test_phdr(in_phdr))
            mvtext_area.set_phdr(in_phdr, i);
    }
    // ToDo(Felix): bss check in Area
    if (mvinfo_area.not_found())
        throw std::runtime_error("Could not find info area segment");
    if (mvtext_area.not_found() && mvtext.max_sz() != 0)
        throw std::runtime_error("Could not find text area segment");

    /* Copy & filter scns for new elf */
    Elf_Scn *scn_in = nullptr, *scn_out;
    Elf_Data *data_in, *data_out;
    GElf_Shdr shdr_in, shdr_out;
    size_t shstrndx;
    elf_getshdrstrndx(e_in, &shstrndx);
    while((scn_in = elf_nextscn(e_in, scn_in)) != nullptr) {
        if (mvinfo_area.is_empty(scn_in) || mvtext_area.is_empty(scn_in))
            continue;
        if ((scn_out = elf_newscn(e_out)) == nullptr)
            errx(1, "elf_newscn failed.");
        mvinfo_area.match(scn_in, scn_out);
        mvtext_area.match(scn_in, scn_out);
        gelf_getshdr(scn_in, &shdr_in);
        gelf_getshdr(scn_out, &shdr_out);
        shdr_out = shdr_in;
        gelf_update_shdr(scn_out, &shdr_out);
        // if scn_in is in area do not copy, generate
        data_in = elf_getdata(scn_in, nullptr);
        if ((data_out = elf_newdata(scn_out)) == nullptr)
            errx(1, "elf_newdata failed.");
        *data_out = *data_in;
        if (shdr_in.sh_type == SHT_NOBITS)
            continue;
        data_out->d_buf = malloc(data_in->d_size); // ToDo(Felix): unique_ptr somehow
        memcpy(data_out->d_buf, data_in->d_buf, data_in->d_size);
    }

    /*
     * AREA:
     * [ ... | mvdata | mvfn | mvvar | mvcs | .bss ]
     * area_ndx : offset into area
     */
    auto area_ndx = 0ul;
    uint64_t vaddr;

    // Section: __multiverse_data_
    size_t mvdata_sz = 0;
    GElf_Shdr mvdata_shdr;
    byte* mvdata_buf;
    mvdata.relocs.clear();
    if (mvdata.size() > 0) {
        mvdata.set_shdr_map(mvinfo_area.start_offset(), mvinfo_area.start_vaddr(), area_ndx);
        mvdata_buf = mvdata.dirty_buf();
        gelf_getshdr(mvdata.scn, &mvdata_shdr);
        vaddr = mvdata_shdr.sh_addr;
        for (auto& e:fns) {
            if (e->is_fixed())
                continue;
            e->set_mvfn_vaddr(vaddr + mvdata_sz);
            mvdata_sz += e->make_mvdata(mvdata_buf+mvdata_sz, &mvdata, vaddr+mvdata_sz);
        }
        mvdata.set_size(mvdata_sz);
    }
    area_ndx += mvdata_sz;

    // Section: __multiverse_fn_
    size_t mvfn_sz = 0;
    GElf_Shdr mvfn_shdr;
    mvfn.relocs.clear();
    byte* mvfn_buf;
    if (mvfn.size() > 0) {
        mvfn.set_shdr_map(mvinfo_area.start_offset(), mvinfo_area.start_vaddr(), area_ndx);
        mvfn_buf = mvfn.dirty_buf();
        gelf_getshdr(mvfn.scn, &mvfn_shdr);
        vaddr = mvfn_shdr.sh_addr;
        for (auto& e:fns) {
            if (e->is_fixed())
                continue;
            mvfn_sz += e->make_info(mvfn_buf+mvfn_sz, &mvfn, vaddr+mvfn_sz);
        }
    }
    mvfn.mark_boundry(&data, mvfn_sz);
    area_ndx += mvfn_sz;

    // Section: __multiverse_var_
    mvvar.relocs.clear();
    size_t mvvar_sz = 0;
    byte* mvvar_buf;
    GElf_Shdr mvvar_shdr;
    if (mvvar.size() > 0) {
        mvvar.set_shdr_map(mvinfo_area.start_offset(), mvinfo_area.start_vaddr(), area_ndx);
        mvvar_buf = mvvar.dirty_buf();
        gelf_getshdr(mvvar.scn, &mvvar_shdr);
        vaddr = mvvar_shdr.sh_addr;
        for (auto& e:vars) {
            if (e->frozen)
                continue;
            mvvar_sz += e->make_info(mvvar_buf+mvvar_sz, &mvvar, vaddr+mvvar_sz);
        }
    }
    mvvar.mark_boundry(&data, mvvar_sz);
    area_ndx += mvvar_sz;

    // Section: __multiverse_callsite_
    mvcs.relocs.clear();
    GElf_Shdr mvcs_shdr;
    byte* mvcs_buf;
    size_t mvcs_sz = 0;
    if (mvcs.size() > 0) {
        mvcs.set_shdr_map(mvinfo_area.start_offset(), mvinfo_area.start_vaddr(), area_ndx);
        mvcs_buf = mvcs.dirty_buf();
        gelf_getshdr(mvcs.scn, &mvcs_shdr);
        vaddr = mvcs_shdr.sh_addr;
        for (auto& e:pps) {
            if ( e->_fn->is_fixed() || e->pp.type == PP_TYPE_X86_JUMP)
                continue;
            mvcs_sz += e->make_info(mvcs_buf+mvcs_sz, &mvcs, vaddr+mvcs_sz);
        }
    }
    mvcs.mark_boundry(&data, mvcs_sz);
    area_ndx += mvcs_sz;

    auto shift = bss.set_shdr_map(mvinfo_area.start_offset(), mvinfo_area.start_vaddr(), area_ndx);
    bss.set_shdr_size(bss.max_sz() + shift);
    mvinfo_area.shrink_phdr(shift);

    update_relocs_sym();
    dynamic.write();

    /* shift sections after area */
    auto area_end = mvinfo_area.start_offset() + area_ndx;
    for (auto& s: secs) {
        gelf_getshdr(s.scn, &s.shdr);
        if (s.shdr.sh_offset < area_end || s.name == ".bss")
            continue;
        s.shdr.sh_offset -= shift;
        gelf_update_shdr(s.scn, &s.shdr);
        elf_flagshdr(s.scn, ELF_C_SET, ELF_F_DIRTY);
        auto d = elf_getdata(s.scn, nullptr);
        elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
    }


    /* Fill new ehdr */
    GElf_Ehdr ehdr_in, ehdr_out;
    gelf_getehdr(e_in, &ehdr_in);
    gelf_getehdr(e_out, &ehdr_out);
    ehdr_out = ehdr_in;
    
    // Section table after sections, adjust for bss (growth in mem, 0 in file)
    // TODO(Felix): shift again
    ///ehdr_out.e_shoff -= shift;
    cout << "shift=0x" << hex << shift << endl;
    gelf_update_ehdr(e_out, &ehdr_out);

    elf_fill(0xcccccccc); // asm(int 0x3) // ToDo(Felix): .dynamic
    // One elf_update should be enough (manual layout)
    //if (elf_update(e_out, ELF_C_NULL) < 0) {
    //    cout << elf_errmsg(elf_errno()) << endl;
    //    errx(1, "elf_update(null) failed.");
    //}
    if (elf_update(e_out, ELF_C_WRITE) < 0) {
        cout << elf_errmsg(elf_errno()) << endl;
        errx(1, "elf_update(write) failed.");
    }
}

/*
 * PRINTING
 */
void Bintail::print_sym() {
    cout << ANSI_COLOR_YELLOW "\nSyms:\n" ANSI_COLOR_RESET; 
    for (auto& sym : syms) {
        cout << "\t" << setw(34) << sym.name << hex
             << " type=" << GELF_ST_TYPE(sym.sym.st_info)
             << " bind=" << GELF_ST_BIND(sym.sym.st_info) << " "
             << sym.sym.st_other << "\t" /* Symbol visibility */
             << sym.sym.st_value << "\t" /* Symbol value */
             << sym.sym.st_size   << "\t" /* Symbol size */
             << endl;
    }
    cout << ANSI_COLOR_YELLOW "\nboundry ptr:" ANSI_COLOR_RESET << hex
         << "\n\tmvvar.start_ptr=0x" << mvvar.start_ptr
         << "\n\tmvvar.stop_ptr=0x" << mvvar.stop_ptr
         << "\n\tmvfn.start_ptr=0x" << mvfn.start_ptr
         << "\n\tmvfn.stop_ptr=0x" << mvfn.stop_ptr
         << "\n\tmvcs.start_ptr=0x" << mvcs.start_ptr
         << "\n\tmvcs.stop_ptr=0x" << mvcs.stop_ptr << "\n";
}

void Bintail::print_reloc() {
#define PRINT_RELOC(S, T) \
    cout << ANSI_COLOR_YELLOW #S ":\n" ANSI_COLOR_RESET; \
    S.print(sizeof(T));

    PRINT_RELOC(mvcs, mv_info_callsite);
    PRINT_RELOC(mvfn, mv_info_fn);
    PRINT_RELOC(mvvar, mv_info_var);
    PRINT_RELOC(mvtext, mv_info_callsite);
    PRINT_RELOC(mvdata, mv_info_callsite);

    cout << ANSI_COLOR_RED "\nRela other:\n" ANSI_COLOR_RESET; 
    for (auto rela : rela_other) {
        cout << hex << " offset=0x" << rela.r_offset
             << " addend=0x" << rela.r_addend;
        for (auto s : secs)
            if (rela.r_offset < s.shdr.sh_addr + s.shdr.sh_size 
                    && rela.r_offset >= s.shdr.sh_addr)
                cout << " - " << s.name;
        cout << endl;
    }
}

void Bintail::print_dyn() {
    cout << ANSI_COLOR_YELLOW ".dynamic: \n" ANSI_COLOR_RESET;
    dynamic.print();
}

void Bintail::print() {
    for (auto& var : vars)
        var->print();
}
