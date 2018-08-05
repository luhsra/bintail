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
    uint8_t* get_func_loc(uint64_t addr);
    void* get_data_loc(uint64_t addr);
    uint64_t get_value(uint64_t addr);
    void set_data_int(uint64_t addr, int value);
    void set_data_ptr(uint64_t addr, uint64_t value);
    void print(size_t elem_sz);
    bool inside(uint64_t addr);
    void set_size(uint64_t nsz);
    std::optional<GElf_Rela*> get_rela(uint64_t vaddr);
    virtual bool probe_rela(GElf_Rela *rela);

    size_t ndx()   { return elf_ndxscn(scn); }
    size_t size()  { return sz; }
    std::byte* dirty_buf();

    std::vector<GElf_Rela> relocs;
    Elf_Scn * scn;
protected:
    Elf * elf;
    uint64_t get_data_offset(uint64_t addr);
    size_t sz;
    uint64_t max_size;
};

template <typename MVInfo>
class MVSection : public Section {
public:
    std::unique_ptr<std::vector<MVInfo>> read(Elf_Scn *scn);
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
MVSection<MVInfo>::read(Elf_Scn *scn) {
    auto v = std::make_unique<std::vector<MVInfo>>();
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    Elf_Data *d = elf_getdata(scn, nullptr);
    const std::byte* buf = static_cast<std::byte*>(d->d_buf);
    for (auto i = 0; i * sizeof(MVInfo) < shdr.sh_size; i++) {
        auto e = *((MVInfo*)buf + i);
        v->push_back(e);
    }
    return v;
}

template <typename MVInfo>
bool MVSection<MVInfo>::probe_rela(GElf_Rela *rela) {
    if (rela->r_offset == start_ptr || rela->r_offset == stop_ptr)
        return true;
    return Section::probe_rela(rela);
}

template <typename MVInfo>
void MVSection<MVInfo>::mark_boundry(Section* data, size_t size) {
    assert(data->inside(start_ptr));
    assert(data->inside(stop_ptr));

    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    data->set_data_ptr(start_ptr, shdr.sh_addr);
    data->set_data_ptr(stop_ptr, shdr.sh_addr+size);

    relocs.push_back(make_rela(start_ptr, shdr.sh_addr));
    relocs.push_back(make_rela(stop_ptr, shdr.sh_addr+size));

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

class TextSection : public Section {
public:
    void add_entry(uint64_t entry);
    void trim(std::set<uint64_t> *active_entries);
private:
    std::set<uint64_t> entries;
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

struct symbol {
    GElf_Sym sym;
    std::string name;
};

class Bintail {
public:
    Bintail(std::string filename);
    ~Bintail();

    void print_reloc();
    void print_sym();
    void print_dyn();
    void print_vars();

    /* Display mv_info_* structs in __multiverse_* section */
    void print();

    void load();
    void write();
    void trim();
    void update_relocs_sym();

    void change(std::string change_str);
    void apply(std::string apply_str);


    void read_info_var(Elf_Scn *scn);
    void read_info_fn(Elf_Scn *scn);
    void read_info_cs(Elf_Scn *scn);

    Section rodata;
    Section data;
    Section text;
    Dynamic dynamic;

    /* MV Sections */
    MVSection<struct mv_info_fn> mvfn;
    MVSection<struct mv_info_var> mvvar;
    MVSection<struct mv_info_callsite> mvcs;
    DataSection mvdata;
    TextSection mvtext;

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

    size_t shstrndx;
    std::vector<struct sec> secs;
};
#endif
