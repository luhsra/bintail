#include <iostream>
#include <string>
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

void Bintail::load() {
    Elf_Scn *scn = nullptr;
    GElf_Shdr shdr;
    while((scn = elf_nextscn(e, scn)) != nullptr) {
        struct sec s;
        gelf_getshdr(scn, &shdr);
        s.scn = scn;
        s.shdr = shdr;
        s.name = elf_strptr(e, shstrndx, shdr.sh_name);
        secs.push_back(s);
    }

    for (const auto& sec : secs) {
        if (sec.name == "__multiverse_var_")
            mvvar.load(e, sec.scn);
        else if (sec.name == "__multiverse_fn_")
            mvfn.load(e, sec.scn);
        else if (sec.name == "__multiverse_callsite_")
            mvcs.load(e, sec.scn);
        else if (sec.name == "__multiverse_data_")
            mvdata.load(e, sec.scn);
        else if (sec.name == "__multiverse_text_")
            mvtext.load(e, sec.scn);
        else if (sec.name == ".rodata")
            rodata.load(e, sec.scn);
        else if (sec.name == ".data")
            data.load(e, sec.scn);
        else if (sec.name == ".text")
            text.load(e, sec.scn);
        else if (sec.name == ".symtab")
            symtab_scn = sec.scn;
        else if (sec.name == ".dynamic")
            dynamic.load(e, sec.scn);
        else if (sec.shdr.sh_type == SHT_RELA && sec.shdr.sh_info == 0)
            reloc_scn = sec.scn;
    }
    read_info_var(mvvar.scn);
    read_info_fn(mvfn.scn);
    read_info_cs(mvcs.scn);
    add_fns();
    link_pp_fn();

    gelf_getshdr(reloc_scn, &shdr);
    auto d = elf_getdata(reloc_scn, nullptr);

    GElf_Rela rela;
    for (size_t i=0; i < d->d_size / shdr.sh_entsize; i++) {
        gelf_getrela(d, i, &rela);
        auto claims = 0u;
        claims += mvvar.probe_rela(&rela);
        claims += mvfn.probe_rela(&rela);
        claims += mvcs.probe_rela(&rela);
        claims += mvtext.probe_rela(&rela);
        claims += mvdata.probe_rela(&rela);
        if (claims == 0)
            rela_other.push_back(rela);
    }

    GElf_Sym sym;
    Elf_Data * d2 = elf_getdata(symtab_scn, nullptr);
    gelf_getshdr(symtab_scn, &shdr);
    shsymtab = shdr.sh_link;
    for (size_t i=0; i < d2->d_size / shdr.sh_entsize; i++) {
        gelf_getsym(d2, i, &sym);
        if (mvcs.inside(sym.st_value))
            mvcs.add_sym(sym);
        else if (mvvar.inside(sym.st_value))
            mvvar.add_sym(sym);
        else if (mvfn.inside(sym.st_value))
            mvfn.add_sym(sym);
        else if (mvtext.inside(sym.st_value))
            mvtext.add_sym(sym);
        else if (mvdata.inside(sym.st_value))
            mvdata.add_sym(sym);
        else if (data.inside(sym.st_value))
            data.add_sym(sym);
        else
            syms_other.push_back(sym);
    }
}

void Bintail::read_info_var(Elf_Scn *scn) {
    auto infos = mvvar.read(scn);
    for (auto e : *infos) {
        auto var = make_unique<MVVar>(e, &rodata, &data);
        vars.push_back(move(var));
    }
}

void Bintail::read_info_fn(Elf_Scn *scn) {
    auto infos = mvfn.read(scn);
    for (auto e : *infos) {
        auto f = make_unique<MVFn>(e, &mvdata, &mvtext);
        auto pp = make_unique<MVPP>(f.get());
        f->add_pp(pp.get());

        fns.push_back(move(f));
        pps.push_back(move(pp));
    }
}

void Bintail::read_info_cs(Elf_Scn *scn) {
    auto infos = mvcs.read(scn);
    for (auto e : *infos) {
        auto pp = make_unique<MVPP>(e, &text, &mvtext);
        pps.push_back(move(pp));
    }
}

void Bintail::update_relocs_sym() {
    vector<GElf_Sym>* svv[] = { 
        &syms_other,
        &data.syms,
        &mvvar.syms,
        &mvdata.syms,
        &mvfn.syms,
        &mvcs.syms, 
        &mvtext.syms,
    };

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
    cnt = 0;
    for (auto v : svv) 
        for (auto s : *v) {
            if (!gelf_update_sym(d2, i++, &s))
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

void Bintail::add_fns() {
    /**
     * find var & save ptr to it
     *    add fn to var.functions_head
     */
    for (auto& var: vars) {
        var->check_fns(fns);
    }
}

/**
 * For all callsites:
 * 1. Find function
 * 2. Create patchpoint
 * 3. Append pp to fn ll
 */
void Bintail::link_pp_fn() {
    for (auto& pp : pps) {
        for (auto& fn : fns) {
            if (fn->location() != pp->function_body )
                continue;
            fn->add_pp(pp.get());
            pp->set_fn(fn.get());
        }
    }
}

void Bintail::change(string change_str) {
    string var_name;
    int value;
    smatch m;

    regex_search(change_str, m, regex(R"((\w+)=(\d+))"));
    var_name = m.str(1);
    value = stoi(m.str(2));

    for (auto& e : vars) {
        if (var_name == e->name())
            e->set_value(value, &data);
    }
}


void Bintail::apply(string change_str) {
    string var_name;
    smatch m;

    regex_search(change_str, m, regex(R"((\w+))"));
    var_name = m.str(1);

    for (auto& e : vars) {
        if (var_name == e->name())
            e->apply(&text, &mvtext);
    }
}

/*
 * TODO: mvtext
 */
void Bintail::trim() {
    // Remove relocs from multiverse sections
    mvvar.relocs.clear();
    mvfn.relocs.clear();
    mvcs.relocs.clear();
    mvdata.relocs.clear();

    size_t mvvar_sz = 0;
    size_t mvfn_sz = 0;
    size_t mvdata_sz = 0;
    size_t mvcs_sz = 0;

    GElf_Shdr shdr;
    byte* buf;
    byte* dbuf;
    uint64_t vaddr;
    uint64_t dvaddr;

    buf = mvvar.dirty_buf();
    gelf_getshdr(mvvar.scn, &shdr);
    vaddr = shdr.sh_addr;
    for (auto& e:vars) {
        if (e->frozen)
            continue;
        mvvar_sz += e->make_info(buf+mvvar_sz, &mvvar, vaddr+mvvar_sz);
    }

    buf = mvfn.dirty_buf();
    dbuf = mvdata.dirty_buf();
    gelf_getshdr(mvfn.scn, &shdr);
    vaddr = shdr.sh_addr;
    gelf_getshdr(mvdata.scn, &shdr);
    dvaddr = shdr.sh_addr;
    for (auto& e:fns) {
        if (e->is_fixed())
            continue;
        e->set_mvfn_vaddr(dvaddr + mvdata_sz);
        mvdata_sz += e->make_mvdata(dbuf+mvdata_sz, &mvdata, dvaddr+mvdata_sz);
        mvfn_sz += e->make_info(buf+mvfn_sz, &mvfn, vaddr+mvfn_sz);
    }

    buf = mvcs.dirty_buf();
    gelf_getshdr(mvcs.scn, &shdr);
    vaddr = shdr.sh_addr;
    for (auto& e:pps) {
        if ( e->_fn->is_fixed() || e->pp.type == PP_TYPE_X86_JUMP)
            continue;
        mvcs_sz += e->make_info(buf+mvcs_sz, &mvcs, vaddr+mvcs_sz);
    }

    // Symbols
    // stop is first after shdr.sh_size
    // mvvar > mvdata > mvfn > mvcs
    auto var_start   = mvvar.get_sym(shsymtab, "__start___multiverse_var_"s).value();
    auto var_stop    = mvdata.get_sym(shsymtab, "__stop___multiverse_var_"s).value();
    auto var_ary     = mvvar.get_sym(shsymtab, "__multiverse_var_ary_"s).value();
    auto fn_start     = mvfn.get_sym(shsymtab, "__start___multiverse_fn_"s).value();
    auto fn_stop      = mvcs.get_sym(shsymtab, "__stop___multiverse_fn_"s).value();
    auto fn_ary       = mvfn.get_sym(shsymtab, "__multiverse_fn_ary_"s).value();
    auto cs_start     = mvcs.get_sym(shsymtab, "__start___multiverse_callsite_"s).value();
    auto cs_stop = find_if(syms_other.begin(), syms_other.end(), [this](auto& sym) {
            auto symname = elf_strptr(e, shsymtab, sym.st_name);
            return "__stop___multiverse_callsite_"s == symname;
            }).base();
    auto cs_ary       = mvcs.get_sym(shsymtab, "__multiverse_callsite_ary_"s).value();
    auto var_stop_ptr = data.get_sym(shsymtab, "__stop___multiverse_var_ptr"s).value();
    auto fn_stop_ptr  = data.get_sym(shsymtab, "__stop___multiverse_fn_ptr"s).value();
    auto cs_stop_ptr  = data.get_sym(shsymtab, "__stop___multiverse_callsite_ptr"s).value();

    // - // Find matching reloc
    // - // stop is first after shdr.sh_size
    // - // mvvar > mvdata > mvfn > mvcs
    // - auto rvar_stop = mvdata.get_rela(var_stop->st_value).value();
    // - auto rfar_stop = mvcs.get_rela(fn_stop->st_value).value();
    // - auto rcar_stop = find_if(rela_other.begin(), rela_other.end(),
    // -         [cs_stop](auto& rela) {
    // -             return cs_stop->st_value == static_cast<uint64_t>(rela.r_addend);
    // -         }).base();

    var_stop->st_value = var_start->st_value+mvvar_sz-sizeof(mv_info_var);
    fn_stop->st_value = fn_start->st_value+mvfn_sz-sizeof(mv_info_fn);
    cs_stop->st_value = cs_start->st_value+mvcs_sz-sizeof(mv_info_callsite);

    var_ary->st_size = mvvar_sz;
    fn_ary->st_size = mvfn_sz;
    cs_ary->st_size = mvcs_sz;

    // ToDo(Felix): Link sym & reloc
    data.set_data_ptr(var_stop_ptr->st_value, var_stop->st_value);
    // - rvar_stop->r_addend = var_stop->st_value;
    data.set_data_ptr(fn_stop_ptr->st_value, fn_stop->st_value);
    // - rfar_stop->r_addend = fn_stop->st_value;
    data.set_data_ptr(cs_stop_ptr->st_value, cs_stop->st_value);
    // - rcar_stop->r_addend = cs_stop->st_value;

    mvvar.set_size(mvvar_sz);
    mvfn.set_size(mvfn_sz);
    mvdata.set_size(mvdata_sz);
    mvcs.set_size(mvcs_sz);

    update_relocs_sym();
    dynamic.write();
}

// See: libelf by example
void Bintail::write() {
    elf_fill(0xc3c3c3c3);
    if (elf_update(e, ELF_C_NULL) < 0) {
        cout << elf_errmsg(elf_errno());
        errx(1, "elf_update(null) failed.");
    }
    if (elf_update(e, ELF_C_WRITE) < 0)
        errx(1, "elf_update(write) failed.");
}

void Bintail::print_sym() {
#define PRINT_SYM(S) \
    cout << ANSI_COLOR_YELLOW #S ":\n" ANSI_COLOR_RESET; \
    S.print_sym(shsymtab);

    PRINT_SYM(mvcs);
    PRINT_SYM(mvfn);
    PRINT_SYM(mvvar);
    PRINT_SYM(mvtext);
    PRINT_SYM(mvdata);

    cout << ANSI_COLOR_RED "\nSym other:\n" ANSI_COLOR_RESET; 
    for (auto& sym : syms_other) {
        cout << "\t" << setw(34) << sym.st_name << hex
             << " type=" << GELF_ST_TYPE(sym.st_info)
             << " bind=" << GELF_ST_BIND(sym.st_info) << " "
             << sym.st_other << "\t" /* Symbol visibility */
             << sym.st_value << "\t" /* Symbol value */
             << sym.st_size   << "\t" /* Symbol size */
             << endl;
    }
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
        var->print(&rodata, &text, &mvtext);
}

Bintail::Bintail(string filename) {
    /**
     * init libelf state
     */ 
    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(1, "libelf init failed");
    if ((fd = open(filename.c_str(), O_RDWR)) == -1) 
        errx(1, "open %s failed. %s", filename.c_str(), strerror(errno));
    if ((e = elf_begin(fd, ELF_C_RDWR, NULL)) == nullptr)
        errx(1, "elf_begin RDWR failed.");
    gelf_getehdr(e, &ehdr);
    elf_getshdrstrndx(e, &shstrndx);

    /*-------------------------------------------------------------------------
     * Manual ELF file layout, remove for smaller file.
     * ToDo(felix): Adjust phdr section after auto re-layout
     *-----------------------------------------------------------------------*/
    elf_flagelf(e, ELF_C_SET, ELF_F_LAYOUT);
}

Bintail::~Bintail() {
    elf_end(e);
    close(fd);
}
