#include <iostream>
#include <iomanip>
#include <optional>
#include <algorithm>
#include <array>
#include <exception>
#include <string.h>
#include <cassert>
#include <memory>
#include <set>

#include "bintail.h"
#include "mvelem.h"

using namespace std;

//------------------DataSection--------------------------------
void TextSection::add_entry(uint64_t entry) {
    assert(inside(entry));
    entries.insert(entry);
}

void TextSection::trim(std::set<uint64_t> *active_entries) {
    //print entries not in active entries
    auto i = mismatch(entries.begin(), entries.end(), active_entries->begin());
    cout << "Mismatch 0x" << hex << *i.first << "\n";
    cout << "   ----  0x" << hex << *i.second << "\n";
}

//------------------DataSection--------------------------------
void DataSection::add_data(MVData* md) {
    ds.push_back(md);
}

void DataSection::write() {
    auto d = elf_getdata(scn, nullptr);
    auto buf = reinterpret_cast<byte*>(d->d_buf);
    auto off = 0ul;

    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    relocs.clear();
    for (auto& e:ds)
        off += e->make_info(buf + off, this, shdr.sh_addr + off);
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);

    set_size(off);
}

//------------------Dynamic------------------------------------
void Dynamic::load(Elf* e, Elf_Scn* s) {
    Section::load(e,s);
    auto d = elf_getdata(scn, nullptr);
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

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
    Elf_Data *d = elf_getdata(scn, nullptr);
    for (auto& dyn : dyns) 
        if (!gelf_update_dyn(d, i++, dyn.get()))
            cout << "Error: gelf_update_dyn() "
                << elf_errmsg(elf_errno()) << endl;
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);

    auto nsz = i * sizeof(GElf_Dyn);
    set_size(nsz);
}

//------------------Section------------------------------------
std::byte* Section::dirty_buf() {
    auto d = elf_getdata(scn, nullptr);
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
    return static_cast<byte*>(d->d_buf);
}

bool Section::probe_rela(GElf_Rela *rela) {
    auto claim = false;
    if ((claim = inside(rela->r_offset)))
        relocs.push_back(*rela);
    return claim;
}

void Section::print(size_t row) {
    Elf_Data *d = elf_getdata(scn, nullptr);
    auto p = (uint8_t *)d->d_buf;
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    auto v = shdr.sh_addr;

    cout << " 0x" << hex << v << ": ";
    for (auto n = 0u; n < d->d_size; n++) {
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

uint64_t Section::get_data_offset(uint64_t addr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    auto offset = addr - shdr.sh_addr;
    if (offset < 0 || offset >= shdr.sh_size)
        throw range_error("Address not inside section - "s + __func__);
    return offset;
}

string Section::get_string(uint64_t addr) {
    auto str = ""s;
    auto offset = get_data_offset(addr);
    auto d = elf_getdata(scn, nullptr);
    auto start = offset - d->d_off;
    const char * name = (char*)d->d_buf+start;
    str += name;
    return str;
}

bool Section::inside(uint64_t addr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
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
    auto d = elf_getdata(scn, nullptr);
    auto start = offset - d->d_off;
    auto buf = static_cast<uint8_t*>(d->d_buf);
    assert(start < d->d_size);
    return static_cast<uint8_t*>(buf+start);
}

void* Section::get_data_loc(uint64_t addr) {
    return get_func_loc(addr);
}

uint64_t Section::get_value(uint64_t addr) {
    return *((uint64_t*)(get_func_loc(addr)));
}

void Section::set_data_int(uint64_t addr, int value) {
    auto offset = get_data_offset(addr);
    auto d = elf_getdata(scn, nullptr);
    auto vptr = (int*)((uint8_t*)d->d_buf + offset); 
    *vptr = value;
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
}

void Section::set_data_ptr(uint64_t addr, uint64_t value) {
    auto offset = get_data_offset(addr);
    auto d = elf_getdata(scn, nullptr);

    auto vptr = (uint64_t*)((uint8_t*)d->d_buf + offset); 
    *vptr = value;

    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
}

void Section::set_size(uint64_t nsz) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    auto d = elf_getdata(scn, nullptr);

    d->d_size = nsz;
    shdr.sh_size = nsz;
    sz = nsz;

    gelf_update_shdr(scn, &shdr);
    elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
}

void Section::load(Elf* e, Elf_Scn* s) {
    elf = e;
    scn = s;
    
    GElf_Shdr shdr;
    gelf_getshdr(s, &shdr);
    max_size = shdr.sh_size;

    assert(elf_getdata(s, nullptr)->d_size == shdr.sh_size);
}
