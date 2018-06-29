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
#include "mvpp.h"

using namespace std;

void Bintail::load() {
    Elf_Scn * scn = nullptr;
    Elf_Scn * reloc_scn = nullptr;
    GElf_Shdr shdr;
    char * shname;

    /* find mv sections */
    while((scn = elf_nextscn(e, scn)) != nullptr) {
        gelf_getshdr(scn, &shdr);
        shname = elf_strptr(e, shstrndx, shdr.sh_name);
        
        if ("__multiverse_var_"s == shname)
            mvvar.load(e, scn);
        else if ("__multiverse_fn_"s == shname)
            mvfn.load(e, scn);
        else if ("__multiverse_callsite_"s == shname)
            mvcs.load(e, scn);
        else if ("__multiverse_data_"s == shname)
            mvdata.load(e, scn);
        else if ("__multiverse_text_"s == shname)
            mvtext.load(e, scn);
        else if (".rodata"s == shname)
            rodata.load(e, scn);
        else if (".data"s == shname)
            data.load(e, scn);
        else if (".text"s == shname)
            text.load(e, scn);
        else if (".symtab"s == shname)
            symbols.load(e, scn);
        else if (shdr.sh_type == SHT_RELA && shdr.sh_info == 0)
            reloc_scn = scn;
        else
            continue;
    }

    assert(data.size() > 0 && text.size() > 0 && rodata.size() > 0);

    parse();
    add_fns();
    add_cs();
    scatter_reloc(reloc_scn);
}

/**
 * For all callsites:
 * 1. Find function
 * 2. Create patchpoint
 * 3. Append pp to fn ll
 */
void Bintail::add_cs() {
    for (auto& cs : mvcs.lst) {
        for (auto& fn : fns) {
            if (fn->location() != cs.function_body )
                continue;

            fn->add_cs(cs, &text, &mvtext);
        }
    }
}

void Bintail::add_fns() {
    for (auto& fn : mvfn.lst) {
        auto f = make_unique<MVFn>(fn, &mvdata, &mvtext);
        fns.push_back(move(f));
    }
    /**
     * find var & save ptr to it
     *    add fn to var.functions_head
     */
    for (auto& var: vars) {
        var->check_fns(fns);
    }
}

void Bintail::parse() {
    for (auto& e : mvvar.lst) {
        auto var = make_unique<MVVar>(e, &rodata, &data);
        vars.push_back(move(var));
    }
}

void Bintail::mark_fixed() {
    for (auto& f : fns) {
        if (f->frozen) {
            mvfn.add_fixed(f->location());
            mvcs.add_fixed(f->location());
        }
    }
    for (auto& v : vars) {
        if (v->frozen) {
            mvvar.add_fixed(v->location());
        }
    }
}


void Bintail::scatter_reloc(Elf_Scn* reloc_scn) {
    GElf_Rela rela;
    GElf_Shdr shdr;

    Elf_Data * d = elf_getdata(reloc_scn, nullptr);
    gelf_getshdr(reloc_scn, &shdr);
    for (size_t i=0; i < d->d_size / shdr.sh_entsize; i++) {
        gelf_getrela(d, i, &rela);

        if (rela.r_info != R_X86_64_RELATIVE) // ToDo(Felix): understand why
            continue;

        if (mvcs.inside(rela.r_offset))
            mvcs.add_rela(d, i, rela.r_offset);
        else if (mvvar.inside(rela.r_offset))
            mvvar.add_rela(d, i, rela.r_offset);
        else if (mvfn.inside(rela.r_offset))
            mvfn.add_rela(d, i, rela.r_offset);
        else if (mvtext.inside(rela.r_offset))
            mvtext.add_rela(d, i, rela.r_offset);
        else if (mvdata.inside(rela.r_offset))
            mvdata.add_rela(d, i, rela.r_offset);
        else if (data.inside(rela.r_offset))
            data.add_rela(d, i, rela.r_offset);
        else
            rela_unmatched.push_back(rela);
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

void Bintail::trim() {
    mark_fixed();

    // Fn
    vector<struct mv_info_fn> nf_lst;
    for (auto& e:mvfn.lst) {
        // if mv_var is fixed skip metadata
        auto i = find_if(mvfn.fixed.begin(), mvfn.fixed.end(),
                [&e](const auto& floc){ return e.function_body == floc; });
        if (i != mvfn.fixed.end())
            continue;
        nf_lst.push_back(e);
    }
    mvfn.regenerate(&symbols, &data, &nf_lst);

    // CS
    vector<struct mv_info_callsite> nc_lst;
    for (auto& e:mvcs.lst) {
        // if mv_var is fixed skip metadata
        auto i = find_if(mvcs.fixed.begin(), mvcs.fixed.end(),
                [&e](const auto& floc){ return e.function_body == floc; });
        if (i != mvcs.fixed.end())
            continue;
        nc_lst.push_back(e);
    }
    mvcs.regenerate(&symbols, &data, &nc_lst);

    // Var
    vector<struct mv_info_var> nv_lst;
    for (auto& e:vars) {
        if (e->frozen)
            continue;
        nv_lst.push_back(e->var);
    }
    mvvar.regenerate(&symbols, &data, &nv_lst);
}

// See: libelf by example
void Bintail::write() {
    if (elf_update(e, ELF_C_NULL) < 0)
        errx(1, "elf_update(null) failed.");

    if (elf_update(e, ELF_C_WRITE) < 0)
        errx(1, "elf_update(write) failed.");
}

void Bintail::print_reloc()
{
#define PRINT_RAW(S, T) \
    cout << ANSI_COLOR_YELLOW #S ":\n" ANSI_COLOR_RESET; \
    S.print(sizeof(T));

    PRINT_RAW(mvcs, mv_info_callsite);
    PRINT_RAW(mvfn, mv_info_fn);
    PRINT_RAW(mvvar, mv_info_var);
    PRINT_RAW(mvtext, mv_info_callsite);
    PRINT_RAW(mvdata, mv_info_callsite);

    cout << ANSI_COLOR_RED "\nRela unmatched:\n" ANSI_COLOR_RESET; 
    for (auto rela : rela_unmatched)
        cout << hex << " offset=0x" << rela.r_offset
             << " addend=0x" << rela.r_addend
             << endl;
}

void Bintail::print_sym() {
    cout << ANSI_COLOR_YELLOW "MVVAR syms: \n" ANSI_COLOR_RESET;
    symbols.print_sym(e, mvvar.ndx() );
    cout << ANSI_COLOR_YELLOW "MVFN syms: \n" ANSI_COLOR_RESET;
    symbols.print_sym(e, mvfn.ndx() );
    cout << ANSI_COLOR_YELLOW "MVCS syms: \n" ANSI_COLOR_RESET;
    symbols.print_sym(e, mvcs.ndx() );
    cout << ANSI_COLOR_YELLOW "DATA syms: \n" ANSI_COLOR_RESET;
    symbols.print_sym(e, data.ndx() );
}

void Bintail::print() {
    for (auto& var : vars)
        var->print(&rodata, &data, &text, &mvtext);
}

Bintail::Bintail(string filename) {
    /**
     * init libelf state
     */ 
    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(1, "libelf init failed");
    if ((fd = open(filename.c_str(), O_RDWR)) == -1) 
        errx(1, "open %s failed.", filename.c_str());
    if ((e = elf_begin(fd, ELF_C_RDWR, NULL)) == nullptr)
        errx(1, "elf_begin RDWR failed.");
    gelf_getehdr(e, &ehdr);
    elf_getshdrstrndx(e, &shstrndx);

    /*-------------------------------------------------------------------------
     * Manual ELF file layout, remove for smaller file.
     * ToDo(felix): Adjust .dynamic section after auto re-layout
     *-----------------------------------------------------------------------*/
    elf_flagelf(e, ELF_C_SET, ELF_F_LAYOUT);

}

Bintail::~Bintail() {
    elf_end(e);
    close(fd);
}
