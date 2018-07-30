#ifndef __BINTAIL_H
#define __BINTAIL_H

#include <vector>
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
    void print_sym(size_t shsymtab);
    bool inside(uint64_t addr);
    void set_size(uint64_t nsz);

    std::optional<GElf_Rela*> get_rela(uint64_t vaddr);
    std::optional<GElf_Sym*> get_sym(size_t sym_ndx, std::string symbol);

    void add_sym(GElf_Sym Sym);
    bool probe_rela(GElf_Rela *rela);

    size_t ndx()   { return elf_ndxscn(scn); }
    size_t size()  { return sz; }

    std::vector<GElf_Rela> relocs;
    std::vector<GElf_Sym> syms;
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
private:
    GElf_Sym s_start;
    GElf_Sym s_start_ptr;
    GElf_Sym s_stop;
    GElf_Sym s_stop_ptr;

    GElf_Rela r_start_ptr;
    GElf_Rela r_stop_ptr;

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

class Bintail {
public:
    Bintail(std::string filename);
    ~Bintail();

    void print_reloc();
    void print_sym();
    void print_dyn();

    /* Display hex view of raw multiverse sections */
    void print_mv_sections();

    /* Display mv_info_* structs in __multiverse_* section */
    void print();

    void load();
    void write();
    void trim();
    void update_relocs_sym();

    void change(std::string change_str);
    void apply(std::string apply_str);

    void link_pp_fn();
    void add_fns();
    void print_vars();

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
    std::vector<GElf_Sym>  syms_other;
private:
    /* Elf file */
    int fd;
    Elf* e;
    GElf_Ehdr ehdr;
    Elf_Scn * reloc_scn;
    Elf_Scn * symtab_scn;

    size_t shsymtab;
    size_t shstrndx;
    std::vector<struct sec> secs;
};
#endif
