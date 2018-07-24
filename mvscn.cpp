#include <iostream>
#include <iomanip>
#include <optional>
#include <algorithm>
#include <array>
#include <exception>
#include <string.h>
#include <cassert>
#include <memory>
#include <gsl/gsl>

#include "bintail.h"
#include "mvvar.h"
#include "mvpp.h"

using namespace std;

//------------------DataSection--------------------------------
void DataSection::clear() {
    ds.clear();
}

void DataSection::add_data(MVData* md) {
    ds.push_back(md);
}

void DataSection::write() {
    relocs.clear();
    auto buf = reinterpret_cast<byte*>(data->d_buf);
    uint64_t off = 0;

    for (auto& e:ds)
        off += e->make_info(buf + off, this, shdr.sh_addr + off);

    set_size(off);
    set_dirty();
}

//------------------Dynamic------------------------------------
void Dynamic::load(Elf* e, Elf_Scn* s) {
    Section::load(e,s);
    auto d = elf_getdata(scn, nullptr);
    for (auto i=0; i * shdr.sh_entsize < d->d_size; i++) {
        auto dyn = make_unique<GElf_Dyn>();
        gelf_getdyn(d, i, dyn.get());
        dyns.push_back(std::move(dyn));
    }
}

void Dynamic::print() {
    for (auto& d : dyns) {
        if (d->d_tag == 0x0)
            continue;
        cout << hex << " type=0x"<< d->d_tag
            << " un=0x" << d->d_un.d_ptr << "\n";
    }
}

GElf_Dyn* Dynamic::get_dyn(int64_t tag) {
    auto it = find_if(dyns.begin(), dyns.end(), [&tag](auto& d) {
            return d->d_tag == tag;
            });
    if (it != dyns.end())
        return (*it).get();
    else
        return nullptr;
}

void Dynamic::write() {
    int i = 0;
    for (auto& dyn : dyns) 
        if (!gelf_update_dyn (data, i++, dyn.get()))
            cout << "Error: gelf_update_dyn() "
                << elf_errmsg(elf_errno()) << endl;

    assert(sizeof(GElf_Dyn) == shdr.sh_entsize);
    auto nsz = i * sizeof(GElf_Dyn);

    set_size(nsz);
    set_dirty();
}

//------------------Section------------------------------------
void Section::print_sym(size_t shsymtab) {
    for (auto& sym : syms) {
        if (sym.st_shndx != ndx())
            continue;

        auto symname = elf_strptr(elf, shsymtab, sym.st_name);
        if (symname[0] == '\0')
            continue;

        cout << "\t" << setw(34) << symname << hex
             << " type=" << GELF_ST_TYPE(sym.st_info)
             << " bind=" << GELF_ST_BIND(sym.st_info) << " "
             << sym.st_other << "\t" /* Symbol visibility */
             << sym.st_value << "\t" /* Symbol value */
             << sym.st_size   << "\t" /* Symbol size */
             << endl;
    }
}

void Section::print(size_t row) {
    auto p = (uint8_t *)data->d_buf;
    auto v = vaddr();

    cout << " 0x" << hex << v << ": ";
    for (auto n = 0u; n < data->d_size; n++) {
        if (auto r = get_rela(v+n); r.has_value())
            cout << ANSI_COLOR_BLUE << "[0x" << r.value()->r_addend << "]";
        else
            cout << ANSI_COLOR_RESET;
        printf("%02x ", *(p+n));
        if (n%4 == 3)   printf(" ");
        if (n%row == row-1) 
            cout << "\n 0x" << hex << v+n+1 << ": ";
    }
    cout << "\n";
}

optional<GElf_Rela*> Section::get_rela(uint64_t vaddr) {
    auto r = find_if(relocs.begin(), relocs.end(),
                [vaddr](const GElf_Rela& r) { return r.r_offset == vaddr; }); 
    if (r == relocs.end())
        return {};
    else
        return r.base();

}

std::optional<GElf_Sym*> Section::get_sym(size_t sym_ndx, string symbol) {
    auto it = find_if(syms.begin(), syms.end(), [sym_ndx,&symbol,this](auto& sym) {
            auto symname = elf_strptr(elf, sym_ndx, sym.st_name);
            return symbol == symname;
            });
    if (it != syms.end())
        return it.base();
    else
        return {};
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

    auto start = offset - data->d_off;
    const char * name = (char*)data->d_buf+start;
    str += name;
    return str;
}

void Section::add_rela(GElf_Rela rela) {
    relocs.push_back(rela);
}

void Section::add_sym(GElf_Sym sym) {
    syms.push_back(sym);
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

    auto start = offset - data->d_off;
    auto buf = static_cast<uint8_t*>(data->d_buf);
    assert(start < data->d_size);
    return static_cast<uint8_t*>(buf+start);

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
    assert(offset < data->d_size);

    auto vptr = (int*)((uint8_t*)data->d_buf + offset); 
    *vptr = value;

    elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
}

void Section::set_data_ptr(uint64_t addr, uint64_t value) {
    auto offset = get_data_offset(addr);

    /* single data obj on read, never add another */
    assert(offset < data->d_size);

    auto vptr = (uint64_t*)((uint8_t*)data->d_buf + offset); 
    *vptr = value;

    elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
}

void Section::set_size(uint64_t nsz) {
    assert(nsz <= sz);
    data->d_size = nsz;
    shdr.sh_size = nsz;
    sz = nsz;
}

void Section::set_dirty() {
    elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
    gelf_update_shdr(scn, &shdr);
    elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
}

void Section::load(Elf* e, Elf_Scn* s) {
    elf = e;
    scn = s;
    gelf_getshdr(s, &shdr);
    sz = shdr.sh_size;
    max_size = shdr.sh_size;
    data = elf_getdata(s, nullptr);
    assert(data->d_size == sz);
}
