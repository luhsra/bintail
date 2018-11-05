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
        throw std::runtime_error("Symbol "s + name + " not found");
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

    /* EHDR */
    gelf_getehdr(e_in, &ehdr_in);

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


    symtab_scn = get_scn(secs, ".symtab").value();
    if (symtab_scn == nullptr)
        throw std::runtime_error("Need symtab for multiverse boundries.");

    /* Must exist */
    reloc_scn_in = get_scn(secs, ".rela.dyn").value(); // also reachable over DYNAMIC section

    Elf_Scn *rodata_scn = get_scn(secs, ".rodata").value();
    rodata.load (rodata_scn);
    scn_handler[rodata_scn] = &rodata;

    Elf_Scn *data_scn = get_scn(secs, ".data").value();
    data.load(data_scn);
    scn_handler[data_scn] = &data;

    Elf_Scn *dynamic_scn = get_scn(secs, ".dynamic").value();
    dynamic.load(dynamic_scn);
    scn_handler[dynamic_scn] = &dynamic;

    Elf_Scn *text_scn = get_scn(secs, ".text").value();
    text.load(text_scn);
    scn_handler[text_scn] = &text;

    Elf_Scn *bss_scn = get_scn(secs, ".bss").value();
    bss.load(bss_scn);
    scn_handler[bss_scn] = &bss;

    Elf_Scn *mvvar_scn = get_scn(secs, "__multiverse_var_").value();
    if (mvvar_scn == nullptr) 
        throw std::runtime_error("Executable has no multiverse variables.\n");
    mvvar.load(mvvar_scn);
    scn_handler[mvvar_scn] = &mvvar;

    /* Sections may not exsist */
    auto mvfn_scn = get_scn(secs, "__multiverse_fn_");
    if (mvfn_scn.has_value()) {
        mvfn.load(mvfn_scn.value());
        scn_handler[mvfn_scn.value()] = &mvfn;
    }
    auto mvcs_scn = get_scn(secs, "__multiverse_callsite_");
    if (mvcs_scn.has_value()) {
        mvcs.load(mvcs_scn.value());
        scn_handler[mvcs_scn.value()] = &mvcs;
    }
    auto mvdata_scn = get_scn(secs, "__multiverse_data_");
    if (mvdata_scn.has_value()) {
        mvdata.load(mvdata_scn.value());
        scn_handler[mvdata_scn.value()] = &mvdata;
    }
    auto mvtext_scn = get_scn(secs, "__multiverse_text_");
    if (mvtext_scn.has_value()) {
        mvtext.load(mvtext_scn.value());
        scn_handler[mvtext_scn.value()] = &mvtext;
    }

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
    try {
    mvvar.start_ptr = sym_value(syms, "__start___multiverse_var_ptr");
    mvvar.stop_ptr  = sym_value(syms, "__stop___multiverse_var_ptr");
    mvfn.start_ptr  = sym_value(syms, "__start___multiverse_fn_ptr");
    mvfn.stop_ptr   = sym_value(syms, "__stop___multiverse_fn_ptr");
    mvcs.start_ptr  = sym_value(syms, "__start___multiverse_callsite_ptr");
    mvcs.stop_ptr   = sym_value(syms, "__stop___multiverse_callsite_ptr");
    } catch (...) {
        cout << "Symbols missing, cannot be tailored\n";
        close(infd);
        exit(0);
    }

    int boundary_sz;
    boundary_sz = sym_value(syms, "__stop___multiverse_var_") - sym_value(syms, "__start___multiverse_var_");
    cout << " var=" << boundary_sz / sizeof(struct mv_info_var) << " ";
    boundary_sz = sym_value(syms, "__stop___multiverse_fn_") - sym_value(syms, "__start___multiverse_fn_");
    cout << " fn=" << boundary_sz  / sizeof(struct mv_info_fn) << " ";
    boundary_sz = sym_value(syms, "__stop___multiverse_callsite_") - sym_value(syms, "__start___multiverse_callsite_");
    cout << " cs=" << boundary_sz / sizeof(struct mv_info_callsite)  << " ";

    for (auto& sym : syms)
        for (auto& fn : fns)
            fn->probe_sym(sym);

    GElf_Rela rela;
    gelf_getshdr(reloc_scn_in, &shdr);
    auto d = elf_getdata(reloc_scn_in, nullptr);
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
    for (auto& v : vars)
        if (var_name == v->name())
            v->set_value(value, &data);
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
    for (auto& v : vars)
        v->apply(&text, &mvtext, guard);
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
    gelf_getshdr(reloc_scn_out, &shdr);
    gelf_getshdr(symtab_scn, &sym_shdr);
    auto d = elf_getdata(reloc_scn_out, nullptr);
    auto d2 = elf_getdata(symtab_scn, nullptr);

    // RELOCS
    int i = 0;
    int cnt = 0;
    for (auto v : rvv) 
        for (auto r : *v) {
            if (r.r_info == R_X86_64_RELATIVE)
                cnt++;
            if (!gelf_update_rela (d, i++, &r))
                throw std::runtime_error("Error: gelf_update_rela() "s + elf_errmsg(elf_errno()));
        }

    assert(sizeof(GElf_Rela) == shdr.sh_entsize);
    shdr.sh_size = i * sizeof(GElf_Rela);
    d->d_size = shdr.sh_size;

    auto dyn_relasz = dynamic.get_dyn(DT_RELASZ).value();
    dyn_relasz->d_un.d_val = shdr.sh_size;

    auto dyn_relacount = dynamic.get_dyn(DT_RELACOUNT);
    if (dyn_relacount.has_value()) {
        auto relacount = dyn_relacount.value();
        relacount->d_un.d_val = cnt;
    }

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
    gelf_update_shdr(reloc_scn_out, &shdr);
    gelf_update_shdr(symtab_scn, &sym_shdr);
    elf_flagshdr(reloc_scn_out, ELF_C_SET, ELF_F_DIRTY);
    elf_flagshdr(symtab_scn, ELF_C_SET, ELF_F_DIRTY);
}

/* Create file until MVInfo data */
void Bintail::init_write(const char *outfile, bool apply_all) {
    if ((outfd = open(outfile, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IXUSR)) == -1) 
        errx(1, "open %s failed. %s", outfile, strerror(errno));
    if ((e_out = elf_begin(outfd, ELF_C_WRITE, NULL)) == nullptr)
        errx(1, "elf_begin outfile failed.");

     // Manual layout: Sections in segments have to be relocated manualy
    elf_flagelf(e_out, ELF_C_SET, ELF_F_LAYOUT);
    gelf_newehdr(e_out, ELFCLASS64);
    gelf_getehdr(e_out, &ehdr_out);
    ehdr_out = ehdr_in;
    bool fpic = (ehdr_in.e_type == ET_DYN);

    /* MV Sections */
    mvdata.set_fns(&fns);
    mvfn.set_fns(&fns);
    mvvar.set_vars(&vars);
    mvcs.set_pps(&pps);
    /* MV Areas */
    mvinfo_area = make_unique<InfoArea>(e_out, fpic, &mvdata, &mvvar, &mvfn, &mvcs, &bss);
    mvtext_area = make_unique<TextArea>(e_out, fpic, &mvtext);

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
        if (mvinfo_area->test_phdr(in_phdr))
            mvinfo_area->set_phdr(in_phdr, i);
        if (mvtext_area->test_phdr(in_phdr))
            mvtext_area->set_phdr(in_phdr, i);
    }
    if (mvinfo_area->not_found())
        throw std::runtime_error("Could not find info area segment");
    if (mvtext_area->not_found() && mvtext.max_sz() != 0)
        throw std::runtime_error("Could not find text area segment");

    /* Copy & filter scns for new elf */
    Elf_Scn *scn_in = nullptr, *scn_out;
    Elf_Data *data_in, *data_out;
    GElf_Shdr shdr_in, shdr_out;
    size_t shstrndx;
    removed_scns = 0;
    elf_getshdrstrndx(e_in, &shstrndx);
    while((scn_in = elf_nextscn(e_in, scn_in)) != nullptr) {
        gelf_getshdr(scn_in, &shdr_in);
        auto it = scn_handler.find(scn_in);
        if (it != scn_handler.end()) {
            auto sec = it->second;
            if (sec->is_needed(apply_all == false) == false) {
                removed_scns++;
                continue;
            }
            if ((scn_out = elf_newscn(e_out)) == nullptr)
                errx(1, "elf_newscn failed.");
            sec->set_out_scn(scn_out);
        } else {
            if ((scn_out = elf_newscn(e_out)) == nullptr)
                errx(1, "elf_newscn failed.");
        }
        if (scn_in == reloc_scn_in)
            reloc_scn_out = scn_out;

        /* Copy scn shdr & data */
        gelf_getshdr(scn_out, &shdr_out);
        shdr_out = shdr_in;
        if (removed_scns != 0 && shdr_in.sh_link > 0)
            shdr_out.sh_link -= removed_scns;
        gelf_update_shdr(scn_out, &shdr_out);

        data_in = elf_getdata(scn_in, nullptr);
        if ((data_out = elf_newdata(scn_out)) == nullptr)
            errx(1, "elf_newdata failed.");
        *data_out = *data_in; // malloc & memcpy ???
    }
}

void Bintail::write() {
    mvinfo_area->generate(&data);

    update_relocs_sym();
    dynamic.write();

    auto area_end = mvinfo_area->end_offset();
    auto shift = bss.new_sz() - bss.old_sz();

    /* shift sections after area */
    GElf_Shdr shdr;
    Elf_Scn *scn = nullptr;
    while ((scn = elf_nextscn(e_out, scn))) {
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_offset < area_end || scn == bss.scn_out)
            continue;
        shdr.sh_offset -= shift;
        gelf_update_shdr(scn, &shdr);
        //elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
        //auto d = elf_getdata(scn, nullptr);
        //elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
    }

    ehdr_out.e_shstrndx -= removed_scns;
    ehdr_out.e_shnum -= removed_scns;
    // Section table after sections, adjust for bss (growth in mem, 0 in file)
    ehdr_out.e_shoff -= shift;
    cout << " shift=" << shift << "\n";
    gelf_update_ehdr(e_out, &ehdr_out);

    elf_fill(0xcccccccc); // asm(int 0x3) // ToDo(Felix): .dynamic fill
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
