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

//------------------Area---------------------------------------
Area::Area(Elf *_e_out, bool _fpic) {
    e_out = _e_out;
    fpic = _fpic;
}

void Area::set_phdr(GElf_Phdr &_phdr, const size_t &_ndx) {
    phdr = _phdr;
    ndx = _ndx;
    found = true;
    area_offset_end = _phdr.p_offset + _phdr.p_filesz;
    area_offset_start = area_offset_end;
    area_vaddr_end = _phdr.p_vaddr + _phdr.p_memsz;
    find_start_of_area();
}

//-----------------TextArea---------------------------------------
TextArea::TextArea(Elf *e_out, bool fpic, Section *_mvtext) :
    Area(e_out, fpic) {
    mvtext = _mvtext;
}

uint64_t TextArea::generate() {
    auto area_ndx = 0ul;
    // ToDo(Felix): this
    return area_ndx;
}

void TextArea::find_start_of_area() {
    GElf_Shdr shdr;
    gelf_getshdr(mvtext->scn_in, &shdr);

    area_offset_start = shdr.sh_offset;
    area_vaddr_start = shdr.sh_addr;
}

bool TextArea::test_phdr(GElf_Phdr &phdr) {
    return mvtext->in_segment(phdr);
}

uint64_t TextArea::size_in_file() {
    return mvtext->size();
}

//------------------InfoArea---------------------------------------
InfoArea::InfoArea(Elf *e_out, bool fpic, MVDataSection *_mvdata, MVVarSection *_mvvar,
        MVFnSection *_mvfn, MVCsSection *_mvcs, BssSection *_bss) :
    Area(e_out, fpic) {
    mvdata = _mvdata;
    mvvar = _mvvar;
    mvfn =  _mvfn;
    mvcs =  _mvcs;
    bss =  _bss;
}

uint64_t InfoArea::size_in_file() {
    return mvdata->max_sz() + mvvar->max_sz()
        + mvfn->max_sz() + mvcs->max_sz();
}

bool InfoArea::test_phdr(GElf_Phdr &phdr) {
    return bss->in_segment(phdr)
        && ( mvdata->in_segment(phdr) || mvdata->max_sz() == 0 )
        && ( mvvar->in_segment(phdr) || mvvar->max_sz() == 0 )
        && ( mvfn->in_segment(phdr) || mvfn->max_sz() == 0 )
        && ( mvcs->in_segment(phdr) || mvcs->max_sz() == 0 );
}

void InfoArea::find_start_of_area() {
    GElf_Shdr shdr;
    Section* secs[] = {mvdata, mvvar, mvfn, mvcs};
    for (auto& s : secs) {
        gelf_getshdr(s->scn_in, &shdr);
        if (area_offset_start > shdr.sh_offset) {
            area_offset_start = shdr.sh_offset;
            area_vaddr_start = shdr.sh_addr;
        }
    }
}

/*
 * InfoAREA:
 * [ ... | mvdata | mvfn | mvvar | mvcs | .bss ]
 */
uint64_t InfoArea::generate(Section *data) {
    auto area_pos = 0ul;

    area_pos += mvdata->generate(fpic, area_offset_start+area_pos, area_vaddr_start+area_pos);
    area_pos += mvfn->generate(fpic, area_offset_start+area_pos, area_vaddr_start+area_pos, data);
    area_pos += mvvar->generate(fpic, area_offset_start+area_pos, area_vaddr_start+area_pos, data);
    area_pos += mvcs->generate(fpic, area_offset_start+area_pos, area_vaddr_start+area_pos, data);

    /* Shift and expand .bss in mem, move to end in file */
    auto shift = bss->generate(area_offset_start + area_pos, area_vaddr_start + area_pos, area_vaddr_end);

    /* Shrink Segment */
    phdr.p_filesz -= shift;
    gelf_update_phdr(e_out, ndx, &phdr);

    return shift;
}

//------------------MVSection--------------------------------
bool MVSection::probe_rela(GElf_Rela *rela) {
    if (rela->r_offset == start_ptr || rela->r_offset == stop_ptr)
        return true;
    return Section::probe_rela(rela);
}

//-----------------MVFnSection-------------------------------
std::unique_ptr<std::vector<struct mv_info_fn>> MVFnSection::read() {
    auto v = std::make_unique<std::vector<struct mv_info_fn>>();
    if (scn_in == nullptr) // Section does not exist
        return v;
    auto d = elf_getdata(scn_in, nullptr);
    if (d == nullptr) // Section has no data
        return v;

    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);

    // ToDo(Felix): stupid casting???
    const std::byte* buf = static_cast<std::byte*>(d->d_buf);
    for (auto i = 0; i * sizeof(struct mv_info_fn) < shdr.sh_size; i++) {
        auto e = *((struct mv_info_fn*)buf + i);
        v->push_back(e);
    }
    return v;
}

uint64_t MVFnSection::generate(bool fpic, uint64_t offset, uint64_t vaddr, Section *data) {
    relocs.clear();
    auto ndx = 0;
    /* no data -> section not needed */
    if (scn_out != nullptr) {
        /* data */
        auto data = elf_getdata(scn_out, nullptr);
        auto buf = static_cast<byte*>(data->d_buf);

        for (auto& e:*fns) {
            if (e->is_fixed())
                continue;
            ndx += e->make_info(fpic, buf+ndx, this, vaddr+ndx);
        }
        data->d_size = ndx;
        elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
        
        /* shdr */
        GElf_Shdr shdr;
        gelf_getshdr(scn_in, &shdr);

        shdr.sh_offset = offset;
        shdr.sh_addr = vaddr;
        shdr.sh_size = ndx;

        gelf_update_shdr(scn_out, &shdr);
        elf_flagshdr(scn_out, ELF_C_SET, ELF_F_DIRTY);
    }
    
    /* start/stop_ptr for libmultiverse */
    data->write_ptr(fpic, start_ptr, vaddr);
    data->write_ptr(fpic, stop_ptr, vaddr+ndx);
    return ndx;
}

bool MVFnSection::is_needed(bool overr) {
    return overr;
}

void MVFnSection::set_fns(std::vector<std::unique_ptr<MVFn>> *_fns) {
    fns = _fns;
}

//-----------------MVVarSection-------------------------------
std::unique_ptr<std::vector<struct mv_info_var>> MVVarSection::read() {
    auto v = std::make_unique<std::vector<struct mv_info_var>>();
    if (scn_in == nullptr) // Section does not exist
        return v;
    auto d = elf_getdata(scn_in, nullptr);
    if (d == nullptr) // Section has no data
        return v;

    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);

    // ToDo(Felix): stupid casting???
    const std::byte* buf = static_cast<std::byte*>(d->d_buf);
    for (auto i = 0; i * sizeof(struct mv_info_var) < shdr.sh_size; i++) {
        auto e = *((struct mv_info_var*)buf + i);
        v->push_back(e);
    }
    return v;
}

uint64_t MVVarSection::generate(bool fpic, uint64_t offset, uint64_t vaddr, Section *data) {
    relocs.clear();
    auto ndx = 0;

    if (scn_out != nullptr) { // no data -> section not needed
        /* data */
        auto data = elf_getdata(scn_out, nullptr);
        auto buf = static_cast<byte*>(data->d_buf);

        for (auto& e:*vars) {
            if (e->frozen)
                continue;
            ndx += e->make_info(fpic, buf+ndx, this, vaddr+ndx);
        }
        data->d_size = ndx;
        elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
        
        /* shdr */
        GElf_Shdr shdr;
        gelf_getshdr(scn_in, &shdr);

        shdr.sh_offset = offset;
        shdr.sh_addr = vaddr;
        shdr.sh_size = ndx;

        gelf_update_shdr(scn_out, &shdr);
        elf_flagshdr(scn_out, ELF_C_SET, ELF_F_DIRTY);
    }
    
    /* start/stop_ptr for libmultiverse */
    data->write_ptr(fpic, start_ptr, vaddr);
    data->write_ptr(fpic, stop_ptr, vaddr+ndx);
    return ndx;
}

bool MVVarSection::is_needed(bool overr) {
    return overr;
}

void MVVarSection::set_vars(std::vector<std::shared_ptr<MVVar>> *_vars) {
    vars = _vars;
}
//-----------------MVCsSection-------------------------------
std::unique_ptr<std::vector<struct mv_info_callsite>> MVCsSection::read() {
    auto v = std::make_unique<std::vector<struct mv_info_callsite>>();
    if (scn_in == nullptr) // Section does not exist
        return v;
    auto d = elf_getdata(scn_in, nullptr);
    if (d == nullptr) // Section has no data
        return v;

    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);

    // ToDo(Felix): stupid casting???
    const std::byte* buf = static_cast<std::byte*>(d->d_buf);
    for (auto i = 0; i * sizeof(struct mv_info_callsite) < shdr.sh_size; i++) {
        auto e = *((struct mv_info_callsite*)buf + i);
        v->push_back(e);
    }
    return v;
}

uint64_t MVCsSection::generate(bool fpic, uint64_t offset, uint64_t vaddr, Section *data) {
    relocs.clear();
    auto ndx = 0;
    if (scn_out != nullptr) { // no data -> section not needed
        /* data */
        auto data = elf_getdata(scn_out, nullptr);
        auto buf = static_cast<byte*>(data->d_buf);

        for (auto& e:*pps) {
            if ( e->_fn->is_fixed() || e->pp.type == PP_TYPE_X86_JUMP)
                continue;
            ndx += e->make_info(fpic, buf+ndx, this, vaddr+ndx);
        }
        data->d_size = ndx;
        elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);

        /* shdr */
        GElf_Shdr shdr;
        gelf_getshdr(scn_in, &shdr);

        shdr.sh_offset = offset;
        shdr.sh_addr = vaddr;
        shdr.sh_size = ndx;

        gelf_update_shdr(scn_out, &shdr);
        elf_flagshdr(scn_out, ELF_C_SET, ELF_F_DIRTY);
    }
    
    /* start/stop_ptr for libmultiverse */
    data->write_ptr(fpic, start_ptr, vaddr);
    data->write_ptr(fpic, stop_ptr, vaddr+ndx);
    return ndx;
}

bool MVCsSection::is_needed(bool overr) {
    return overr;
}

void MVCsSection::set_pps(std::vector<std::unique_ptr<MVPP>> *_pps) {
    pps = _pps;
}
//------------------MVDataSection--------------------------------
uint64_t MVDataSection::generate(bool fpic, uint64_t offset, uint64_t vaddr) {
    relocs.clear();
    if (scn_out == nullptr) { // no data -> section not needed
        return 0;
    }

    /* data */
    auto data = elf_getdata(scn_out, nullptr);
    auto buf = static_cast<byte*>(data->d_buf);

    auto ndx = 0;
    for (auto& e:*fns) {
        if (e->is_fixed())
            continue;
        e->set_mvfn_vaddr(vaddr + ndx);
        ndx += e->make_mvdata(fpic, buf+ndx, this, vaddr+ndx);
    }
    data->d_size = ndx;
    elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
    
    /* shdr */
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);

    shdr.sh_offset = offset;
    shdr.sh_addr = vaddr;
    shdr.sh_size = ndx;
    //shdr.sh_addralign = 1; // ToDo(Felix): why 16?

    gelf_update_shdr(scn_out, &shdr);
    elf_flagshdr(scn_out, ELF_C_SET, ELF_F_DIRTY);

    return ndx;
}

bool MVDataSection::is_needed(bool overr) {
    return overr;
}

void MVDataSection::set_fns(std::vector<std::unique_ptr<MVFn>> *_fns) {
    fns = _fns;
}
//------------------BssSection---------------------------------
uint64_t BssSection::generate(uint64_t offset, uint64_t vaddr_start, uint64_t vaddr_end) {
    /* shdr */
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);

    auto old_offset = shdr.sh_offset;
    shdr.sh_offset = offset;
    shdr.sh_addr = vaddr_start;
    shdr.sh_size = vaddr_end - vaddr_start;
    auto shift = old_offset - offset;

    gelf_update_shdr(scn_out, &shdr);
    elf_flagshdr(scn_out, ELF_C_SET, ELF_F_DIRTY);

    return shift;
}

uint64_t BssSection::old_sz() {
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);
    return shdr.sh_size;
}

uint64_t BssSection::new_sz() {
    GElf_Shdr shdr;
    gelf_getshdr(scn_out, &shdr);
    return shdr.sh_size;
}

//------------------Dynamic------------------------------------
void Dynamic::load(Elf_Scn *scn_in) {
    Section::load(scn_in);
    auto d = elf_getdata(scn_in, nullptr);
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);

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

std::optional<GElf_Dyn*> Dynamic::get_dyn(int64_t tag) {
    auto it = find_if(dyns.begin(), dyns.end(), [&tag](auto& d) {
            return d->d_tag == tag; });
    if (it != dyns.end())
        return (*it).get();
    else
        return {};
}

void Dynamic::write() {
    /* data */
    int i = 0;
    auto d = elf_getdata(scn_out, nullptr);
    for (auto& dyn : dyns) 
        if (!gelf_update_dyn(d, i++, dyn.get()))
            cout << "Error: gelf_update_dyn() " << elf_errmsg(elf_errno()) << endl;
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);

    /* shdr */
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);

    shdr.sh_size = i * sizeof(GElf_Dyn);

    gelf_update_shdr(scn_out, &shdr);
    elf_flagshdr(scn_out, ELF_C_SET, ELF_F_DIRTY);
}

//------------------Section------------------------------------
void Section::add_rela(uint64_t source, uint64_t target) {
    GElf_Rela rela;
    rela.r_addend = target;
    rela.r_info = R_X86_64_RELATIVE;
    rela.r_offset = source;
    relocs.push_back(rela);
}

const std::byte* Section::in_buf() {
    auto d = elf_getdata(scn_in, nullptr);
    return static_cast<byte*>(d->d_buf);
}

const std::byte* Section::in_buf(uint64_t addr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);
    if (shdr.sh_size > addr)
        throw std::runtime_error("Address not in section.");
    return in_buf()+(addr-shdr.sh_addr);
}

std::byte* Section::out_buf() {
    if (scn_out == nullptr)
        throw std::runtime_error("Section does not exsist");
    auto d = elf_getdata(scn_out, nullptr);
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
    return static_cast<byte*>(d->d_buf);
}

std::byte* Section::out_buf(uint64_t addr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn_out, &shdr);
    return out_buf()+(addr-shdr.sh_addr);
}

bool Section::probe_rela(GElf_Rela *rela) {
    auto claim = false;
    if ((claim = inside(rela->r_offset)))
        relocs.push_back(*rela);
    return claim;
}

uint64_t Section::read_ptr(uint64_t address) {
    GElf_Shdr shdr;
    gelf_getshdr(scn_out, &shdr);
    auto d = elf_getdata(scn_out, nullptr);

    auto off = address - shdr.sh_addr;
    if (address < shdr.sh_addr)
        throw std::runtime_error("Section read error, addr to low");
    if (off > d->d_size)
        throw std::runtime_error("Section read error, addr to high");

    auto buf = static_cast<const uint8_t*>(d->d_buf);
    auto dest = reinterpret_cast<const uint64_t*>(buf+off);

    return *dest;
}

void Section::write_ptr(bool fpic, uint64_t address, uint64_t destination) {
    GElf_Shdr shdr;
    gelf_getshdr(scn_out, &shdr);
    auto d = elf_getdata(scn_out, nullptr);

    auto off = address - shdr.sh_addr;
    if (address < shdr.sh_addr)
        throw std::runtime_error("Section write error, addr to low");
    if (off > d->d_size)
        throw std::runtime_error("Section write error, addr to high");

    auto buf = static_cast<uint8_t*>(d->d_buf);
    auto dest = reinterpret_cast<uint64_t*>(buf+off);

    *dest = destination;
    if (fpic) {
        add_rela(address, destination);
    }
}

bool Section::is_needed(bool overr) {
    (void) overr;
    return true;
}

void Section::set_out_scn(Elf_Scn *_scn_out) {
    scn_out = _scn_out;
}

void Section::print(size_t row) {
    Elf_Data *d = elf_getdata(scn_in, nullptr);
    if (d == nullptr) {
        cout << ANSI_COLOR_RED "<Section has no data.>\n";
        return;
    }
    auto p = (uint8_t *)d->d_buf;
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);

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

string Section::get_string(uint64_t addr) {
    return {reinterpret_cast<const char*>(in_buf(addr))};
}

bool Section::is_nobits() {
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);
    return shdr.sh_type == SHT_NOBITS;
}

bool Section::inside(uint64_t addr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);
    bool not_above = addr < shdr.sh_addr + shdr.sh_size;
    bool not_below = addr >= shdr.sh_addr;
    return not_above && not_below;
}

bool Section::in_segment(const GElf_Phdr &phdr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn_in, &shdr);
    // last section in mvinfo_area bss
    bool last_nobits = shdr.sh_offset == phdr.p_offset + phdr.p_filesz
        && shdr.sh_type == SHT_NOBITS && shdr.sh_size > 0;
    bool not_above = shdr.sh_offset < phdr.p_offset + phdr.p_filesz;
    bool not_below = shdr.sh_offset >= phdr.p_offset;
    return (not_above && not_below) || last_nobits;
}

void Section::fill(uint64_t addr, byte value, size_t len) {
    auto b = out_buf(addr);
    for(auto i=0ul; i<len; i++)
        b[i] = value;
}

void Section::load(Elf_Scn* s) {
    scn_in = s;
    if (scn_in == nullptr) {
        max_size = 0;
        return;
    }
    
    GElf_Shdr shdr;
    gelf_getshdr(s, &shdr);
    max_size = shdr.sh_size;

    assert(elf_getdata(s, nullptr)->d_size == shdr.sh_size);
}
