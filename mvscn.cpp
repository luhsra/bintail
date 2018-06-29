#include <iostream>
#include <iomanip>
#include <algorithm>
#include <exception>
#include <string.h>
#include <cassert>
#include <gsl/gsl>

using namespace std;
using namespace std;

#include "bintail.h"
#include "mvvar.h"
#include "mvpp.h"

//------------------FnSection----------------------------------
void FnSection::load(Elf* e, Elf_Scn* s) {
    elf = e;
    scn = s;
    gelf_getshdr(s, &shdr);

    Elf_Data * d = nullptr;
    while ((d = elf_getdata(scn, d)) != nullptr) {
        for (auto i = 0; i * sizeof(struct mv_info_fn) < d->d_size; i++) {
            lst.push_back(*((struct mv_info_fn*)d->d_buf + i));
            sz++;
        }
    }
}

void FnSection::regenerate(Symbols *syms, Section* data, vector<struct mv_info_fn>* nlst) {
    auto d = elf_getdata(scn, nullptr);
    auto buf = (struct mv_info_fn*)d->d_buf;
    copy(nlst->begin(), nlst->end(), buf);
    auto size = nlst->size()*sizeof(struct mv_info_fn);

    auto sym = syms->get_sym_val("__stop___multiverse_fn_ptr"s);
    uint64_t sec_end_old = data->get_value(sym);
    uint64_t sec_end_new = sec_end_old - shdr.sh_size + size;

    data->set_data_ptr(sym, sec_end_new);
    d->d_size = size;
    shdr.sh_size = size;
    set_dirty();
}

//------------------CsSection----------------------------------
void CsSection::load(Elf* e, Elf_Scn* s) {
    elf = e;
    scn = s;
    gelf_getshdr(s, &shdr);

    Elf_Data * d = nullptr;
    while ((d = elf_getdata(scn, d)) != nullptr) {
        for (auto i = 0; i * sizeof(struct mv_info_callsite) < d->d_size; i++) {
            lst.push_back(*((struct mv_info_callsite*)d->d_buf + i));
            sz++;
        }
    }
}

void CsSection::regenerate(Symbols *syms, Section* data, vector<struct mv_info_callsite>* nlst) {
    auto d = elf_getdata(scn, nullptr);
    auto buf = (struct mv_info_callsite*)d->d_buf;
    copy(nlst->begin(), nlst->end(), buf);
    auto size = nlst->size()*sizeof(struct mv_info_callsite);

    auto sym = syms->get_sym_val("__stop___multiverse_callsite_ptr"s);
    uint64_t sec_end_old = data->get_value(sym);
    uint64_t sec_end_new = sec_end_old - shdr.sh_size + size;

    data->set_data_ptr(sym, sec_end_new);
    d->d_size = size;
    shdr.sh_size = size;
    set_dirty();
}

//------------------Symbols------------------------------------
void Symbols::load(Elf* e, Elf_Scn* s) {
    elf = e;
    scn = s;
    gelf_getshdr(s, &shdr);

    auto d = elf_getdata(scn, nullptr);
    for (size_t i=1; i < d->d_size / shdr.sh_entsize; i++) {
        auto sym = make_unique<GElf_Sym>();
        gelf_getsym(d, i, sym.get());
        syms.push_back(std::move(sym));
    }
}

size_t Symbols::get_sym_val(string symbol) {
    for (auto& sym : syms) {
        auto symname = elf_strptr(elf, shdr.sh_link, sym->st_name);
        if (symbol == symname)
            return sym->st_value;
    }
    return 0;
}

void Symbols::print_sym(Elf * elf, size_t shndx) {
    for (auto& sym : syms) {
        if (sym->st_shndx != shndx)
            continue;

        auto symname = elf_strptr(elf, shdr.sh_link, sym->st_name);
        if (symname[0] == '\0')
            continue;

        cout << "\t" << setw(34) << symname << hex
             << " type=" << GELF_ST_TYPE(sym->st_info)
             << " bind=" << GELF_ST_BIND(sym->st_info) << " "
             << sym->st_other << "\t" /* Symbol visibility */
             << sym->st_value << "\t" /* Symbol value */
             << sym->st_size   << "\t" /* Symbol size */
             << endl;
    }
}

//------------------Section------------------------------------
void Section::print(size_t row) {
    auto data = elf_getdata(scn, nullptr);

    auto p = (uint8_t *)data->d_buf;
    auto v = vaddr();

    cout << " 0x" << hex << v << ": ";
    for (auto n = 0u; n < data->d_size; n++) {
        if (rela_vaddr_ndx.find(v+n) != rela_vaddr_ndx.end())
            cout << ANSI_COLOR_BLUE;
        else
            cout << ANSI_COLOR_RESET;
        printf("%02x ", *(p+n));
        if (n%4 == 3)   printf(" ");
        if (n%row == row-1) 
            cout << "\n 0x" << hex << v+n << ": ";
    }
    cout << "\n";
}

uint64_t Section::get_data_offset(uint64_t addr) {
    auto offset = addr - shdr.sh_addr;
    if (offset < 0 || offset >= shdr.sh_size)
        throw range_error("Address not inside section - "s + __func__);
    return offset;
}

string Section::get_string(uint64_t addr) {
    string str("");
    auto offset = get_data_offset(addr);

    Elf_Data * d = nullptr;
    while ((d = elf_getdata(scn, d)) != nullptr) {
        if ((int)offset < d->d_off || offset >= d->d_off + d->d_size)
            continue;
        auto start = offset - d->d_off;
        const char * name = (char*)d->d_buf+start;
        size_t len = strlen(name);
        assert(start + len < d->d_size);
        assert(name[len] == '\0');
        str += name;
        break; // can clip strings
    }
    return str;
}

void Section::add_rela(Elf_Data* d, uint64_t index, uint64_t vaddr) {
    rela_data = d;
    rela_vaddr_ndx[vaddr] = index;
}

bool Section::inside(uint64_t addr) {
    bool not_above = addr < shdr.sh_addr + shdr.sh_size;
    bool not_below = addr >= shdr.sh_addr;
    return not_above && not_below;
}

/**
 * get ptr into data buffer where the function is mapped
 * ToDo(Felix): Use something else
 */
uint8_t* Section::get_func_loc(uint64_t addr) {
    auto offset = get_data_offset(addr);

    Elf_Data * d = nullptr;
    while ((d = elf_getdata(scn, d)) != nullptr) {
        if ((int)offset < d->d_off || offset >= d->d_off + d->d_size)
            continue;
        auto start = offset - d->d_off;
        auto buf = static_cast<uint8_t*>(d->d_buf);
        assert(start < d->d_size);
        return static_cast<uint8_t*>(buf+start);
    }
    assert(false);
    return nullptr;
}

void* Section::get_data_loc(uint64_t addr) {
    return get_func_loc(addr);
}

uint64_t Section::get_value(uint64_t addr) {
    return *((uint64_t*)(get_func_loc(addr)));
}

void Section::set_data_int(uint64_t addr, int value) {
    auto offset = get_data_offset(addr);

    /* single data obj on read, never add another */
    auto d = elf_getdata(scn, nullptr);
    assert(offset < d->d_size);

    auto vptr = (int*)((uint8_t*)d->d_buf + offset); 
    *vptr = value;

    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
}

void Section::set_data_ptr(uint64_t addr, uint64_t value) {
    auto offset = get_data_offset(addr);

    /* single data obj on read, never add another */
    auto d = elf_getdata(scn, nullptr);
    assert(offset < d->d_size);

    auto vptr = (uint64_t*)((uint8_t*)d->d_buf + offset); 
    *vptr = value;

    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
}

void Section::set_dirty() {
    auto d = elf_getdata(scn, nullptr);
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
    gelf_update_shdr(scn, &shdr);
    elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
}

void Section::load(Elf* e, Elf_Scn* s) {
    elf = e;
    scn = s;
    gelf_getshdr(s, &shdr);
    sz = shdr.sh_size;
    max_size = shdr.sh_size;
}

//---------------------VarSection----------------------------------------------
void VarSection::regenerate(Symbols *syms, Section* data, vector<struct mv_info_var>* nlst) {
    auto d = elf_getdata(scn, nullptr);
    auto buf = (struct mv_info_var*)d->d_buf;
    copy(nlst->begin(), nlst->end(), buf);

    auto size = nlst->size()*sizeof(struct mv_info_var);

    auto sym = syms->get_sym_val("__stop___multiverse_var_ptr"s);
    uint64_t sec_end_old = data->get_value(sym);
    uint64_t sec_end_new = sec_end_old - shdr.sh_size + size;

    data->set_data_ptr(sym, sec_end_new);
    d->d_size = size;
    shdr.sh_size = size;
    set_dirty();
}

void VarSection::load(Elf* e, Elf_Scn * s) {
    elf = e;
    scn = s;
    gelf_getshdr(s, &shdr);

    Elf_Data * d = nullptr;
    while ((d = elf_getdata(scn, d)) != nullptr) {
        for (auto i = 0; i * sizeof(struct mv_info_var) < d->d_size; i++) {
            lst.push_back(*((struct mv_info_var*)d->d_buf + i));
            sz++;
        }
    }
}
