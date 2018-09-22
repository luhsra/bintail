#ifndef __BINTAIL_H
#define __BINTAIL_H

#include <vector>
#include <set>
#include <memory>
#include <optional>
#include <map>
#include <string>
#include <cstddef>
#include <gelf.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

class MVVar;
class MVFn;
class MVPP;
class MVData;

const GElf_Rela make_rela(uint64_t source, uint64_t target);

class Section {
public:
    Section() :sz{0} {}

    void load(Elf * elf, Elf_Scn * s);
    std::string get_string(uint64_t addr);
    void fill(uint64_t addr, std::byte value, size_t len);
    void print(size_t elem_sz);
    bool inside(uint64_t addr);
    void set_size(uint64_t nsz);
    int64_t set_shdr_map(uint64_t offset, uint64_t vaddr, uint64_t addend);
    void set_shdr_size(uint64_t size);
    std::optional<GElf_Rela*> get_rela(uint64_t vaddr);
    virtual bool probe_rela(GElf_Rela *rela);
    void add_rela(uint64_t source, uint64_t target);
    bool in_segment(const GElf_Phdr &phdr);
    uint64_t get_offset();

    constexpr size_t size()  { return sz; }
    constexpr size_t max_sz()  { return max_size; }
    std::byte* dirty_buf();
    std::byte* dirty_buf(uint64_t addr);
    const std::byte* buf();
    const std::byte* buf(uint64_t addr);

    std::vector<GElf_Rela> relocs;
    Elf_Scn * scn;
protected:
    Elf * elf;
    uint64_t get_offset(uint64_t addr);
    size_t sz;
    uint64_t max_size;
};

template <typename MVInfo>
class MVSection : public Section {
public:
    std::unique_ptr<std::vector<MVInfo>> read();
    bool probe_rela(GElf_Rela *rela);
    void mark_boundry(Section* data, size_t size);

    uint64_t start_ptr;
    uint64_t stop_ptr;
private:
    void add_data(MVData* );
};

//------------------MVSection--------------------------------
template <typename MVInfo>
std::unique_ptr<std::vector<MVInfo>>
MVSection<MVInfo>::read() {
    auto v = std::make_unique<std::vector<MVInfo>>();
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    Elf_Data *d = elf_getdata(scn, nullptr);
    if (d == nullptr) // Section has no data
        return std::move(v);

    const std::byte* buf = static_cast<std::byte*>(d->d_buf);
    for (auto i = 0; i * sizeof(MVInfo) < shdr.sh_size; i++) {
        auto e = *((MVInfo*)buf + i);
        v->push_back(e);
    }
    return std::move(v);
}

template <typename MVInfo>
bool MVSection<MVInfo>::probe_rela(GElf_Rela *rela) {
    if (rela->r_offset == start_ptr || rela->r_offset == stop_ptr)
        return true;
    return Section::probe_rela(rela);
}

template <typename MVInfo>
void MVSection<MVInfo>::mark_boundry(Section* data, size_t size) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    reinterpret_cast<uint64_t*>(data->dirty_buf(start_ptr))[0] = shdr.sh_addr;
    add_rela(start_ptr, shdr.sh_addr);
    reinterpret_cast<uint64_t*>(data->dirty_buf(stop_ptr))[0] = shdr.sh_addr+size;
    add_rela(stop_ptr, shdr.sh_addr+size);

    set_size(size);
}
//-----------------------------------------------------------

class DataSection : public Section {
public:
    void add_data(MVData* );
    void write();
private:
    std::vector<MVData*> ds;
};

class Dynamic : public Section {
public:
    void load(Elf* elf, Elf_Scn * s);
    void write();
    void print();
    GElf_Dyn* get_dyn(int64_t tag);
private:
    std::vector<std::unique_ptr<GElf_Dyn>> dyns;
};

struct sec {
    Elf_Scn *scn;
    GElf_Shdr shdr;
    std::string name;
};

struct load_seg {
    size_t ndx;
    GElf_Phdr phdr;
};

struct symbol {
    GElf_Sym sym;
    std::string name;
};

class Bintail {
public:
    Bintail(std::string filename);
    ~Bintail();

    void print(); // Display mv_info_* structs in __multiverse_* section
    void print_reloc();
    void print_sym();
    void print_dyn();
    void print_vars();

    void write();
    void trim();
    void update_relocs_sym();

    void change(std::string change_str);
    void apply(std::string apply_str, bool guard);
    void apply_all(bool guard);

    Section rodata;
    Section data;
    Section text;
    Section bss;
    Dynamic dynamic;

    /* MV Sections */
    MVSection<struct mv_info_fn> mvfn;
    MVSection<struct mv_info_var> mvvar;
    MVSection<struct mv_info_callsite> mvcs;
    DataSection mvdata;
    Section mvtext;

    std::vector<std::shared_ptr<MVVar>> vars;
    std::vector<std::unique_ptr<MVFn>> fns;
    std::vector<std::unique_ptr<MVPP>> pps;

    std::vector<GElf_Rela> rela_other;
    std::vector<symbol>  syms;
private:
    /* Elf file */
    int fd;
    Elf* e;
    GElf_Ehdr ehdr;
    Elf_Scn * reloc_scn;
    Elf_Scn * symtab_scn;
    uint64_t area_start_offset;
    uint64_t area_start_vaddr;
    size_t area_phdr_ndx;
    GElf_Phdr area_phdr;

    size_t shstrndx;
    std::vector<struct sec> secs;
    std::vector<struct load_seg> load_segs;
};
#endif
