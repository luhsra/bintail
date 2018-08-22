#include <iostream>
#include <iomanip>
#include <optional>
#include <algorithm>
#include <array>
#include <exception>
#include <string>
#include <string.h>
#include <cassert>
#include <memory>
#include <set>

#include "bintail.h"
#include "mvelem.h"

using namespace std;

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
            return d->d_tag == tag; });
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
void Section::add_rela(uint64_t source, uint64_t target) {
    GElf_Rela rela;
    rela.r_addend = target;
    rela.r_info = R_X86_64_RELATIVE;
    rela.r_offset = source;
    relocs.push_back(rela);
}

const std::byte* Section::buf() {
    auto d = elf_getdata(scn, nullptr);
    return static_cast<byte*>(d->d_buf);
}

const std::byte* Section::buf(uint64_t addr) {
    return buf()+get_offset(addr);
}

std::byte* Section::dirty_buf() {
    auto d = elf_getdata(scn, nullptr);
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
    return static_cast<byte*>(d->d_buf);
}

std::byte* Section::dirty_buf(uint64_t addr) {
    return dirty_buf()+get_offset(addr);
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

uint64_t Section::get_offset(uint64_t addr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    auto offset = addr - shdr.sh_addr;
    assert(offset < 0 || offset >= sz);
    return offset;
}

string Section::get_string(uint64_t addr) {
    auto offset = get_offset(addr);
    return {reinterpret_cast<const char*>(buf()) + offset};
}

bool Section::inside(uint64_t addr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    bool not_above = addr < shdr.sh_addr + shdr.sh_size;
    bool not_below = addr >= shdr.sh_addr;
    return not_above && not_below;
}

bool Section::in_segment(GElf_Phdr &phdr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    bool not_above = shdr.sh_offset < phdr.p_offset + phdr.p_filesz;
    bool not_below = shdr.sh_offset >= phdr.p_offset;
    return not_above && not_below;
}

uint64_t Section::get_offset() {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    return shdr.sh_offset;
}

void Section::fill(uint64_t addr, byte value, size_t len) {
    auto b = dirty_buf() + get_offset(addr);
    for(auto i=0ul; i<len; i++)
        b[i] = value;
}

int64_t Section::set_shdr_map(uint64_t offset, uint64_t vaddr, uint64_t addend) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    int64_t offset_shift = shdr.sh_offset;
    shdr.sh_offset = offset + addend;
    shdr.sh_addr = vaddr + addend;
    offset_shift -= shdr.sh_offset;

    gelf_update_shdr(scn, &shdr);
    elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
    return offset_shift;
}

void Section::set_shdr_size(uint64_t nsz) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    shdr.sh_size = nsz;

    gelf_update_shdr(scn, &shdr);
    elf_flagshdr(scn, ELF_C_SET, ELF_F_DIRTY);
}

void Section::set_size(uint64_t nsz) {
    sz = nsz;
    set_shdr_size(nsz);
    elf_getdata(scn, nullptr)->d_size = nsz;
}

void Section::load(Elf* e, Elf_Scn* s) {
    elf = e;
    scn = s;
    
    GElf_Shdr shdr;
    gelf_getshdr(s, &shdr);
    max_size = shdr.sh_size;

    assert(elf_getdata(s, nullptr)->d_size == shdr.sh_size);
}
