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
        else
            continue;
    }

    assert(data.size() > 0 && text.size() > 0 && rodata.size() > 0);

    mvvar.parse(&rodata, &data);
    mvvar.add_fns(&mvfn, &mvdata, &mvtext);
    mvvar.add_cs(&mvcs, &text);
}

void Bintail::change(string change_str) {
    string var_name;
    int value;
    smatch m;

    regex_search(change_str, m, regex(R"((\w+)=(\d+))"));
    var_name = m.str(1);
    value = stoi(m.str(2));

    mvvar.set_var(var_name, value, &data);
}

void Bintail::apply(string change_str) {
    string var_name;
    smatch m;

    regex_search(change_str, m, regex(R"((\w+))"));
    var_name = m.str(1);

    mvvar.apply_var(var_name, &text, &mvtext);
}

void Bintail::trim() {
    mvvar.mark_fixed(&mvfn, &mvcs);
    mvfn.regenerate(&symbols, &data);
    mvcs.regenerate(&symbols, &data);
    mvvar.regenerate(&symbols, &data);
}

// See: libelf by example
void Bintail::write() {
    if (elf_update(e, ELF_C_NULL) < 0)
        errx(1, "elf_update(null) failed.");

    if (elf_update(e, ELF_C_WRITE) < 0)
        errx(1, "elf_update(write) failed.");
}

//void Bintail::print_reloc()
//{
//    GElf_Rela rela;
//    GElf_Shdr shdr;
//
//    Elf_Scn * scn = nullptr;
//    while((scn = elf_nextscn(e, scn)) != nullptr) {
//        gelf_getshdr(scn, &shdr);
//
//        if (shdr.sh_type != SHT_RELA)
//            continue;
//
//        printf("%s: link=%d info=%d\n", 
//                elf_strptr(e, shstrndx, shdr.sh_name),
//                shdr.sh_link, shdr.sh_info);
//
//        Elf_Data * data = nullptr;
//        while ((data = elf_getdata(scn, data)) != nullptr) {
//            for (size_t i=0; i < data->d_size / shdr.sh_entsize; i++) {
//                gelf_getrela(data, i, &rela);
//                printf("\tO: %lx, I: %lx, A: %lx\n",
//                        rela.r_offset, rela.r_info, rela.r_addend);
//            }
//        }
//    }
//}

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
    mvvar.print(&rodata, &data, &text);
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
