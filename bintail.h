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
    void set_dirty();
    void print(size_t elem_sz);
    void print_sym(size_t shsymtab);
    bool inside(uint64_t addr);
    void set_size(uint64_t nsz);

    std::optional<GElf_Rela*> get_rela(uint64_t vaddr);
    std::optional<GElf_Sym*> get_sym(size_t sym_ndx, std::string symbol);

    void add_rela(GElf_Rela rela);
    void add_sym(GElf_Sym Sym);

    size_t ndx()   { return elf_ndxscn(scn); }
    size_t vaddr() { return shdr.sh_addr; }
    uint64_t off() { return shdr.sh_offset; }
    size_t size()  { return sz; }
    std::byte* buf() { return reinterpret_cast<std::byte*>(data->d_buf); }

    std::vector<GElf_Rela> relocs;
    std::vector<GElf_Sym> syms;
protected:
    Elf_Scn * scn;
    Elf_Data * data;
    Elf * elf;
    uint64_t get_data_offset(uint64_t addr);
    GElf_Shdr shdr;
    size_t sz;
    uint64_t max_size;
};

class DataSection : public Section {
public:
    void add_data(MVData* );
    void write();
    void clear();
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
    uint64_t addr;
    uint64_t size;
    uint64_t off;
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
    void scatter_reloc_sym(Elf_Scn* reloc_scn, Elf_Scn* symtab_scn);

    void link_pp_fn();
    void add_fns();
    void print_vars();

    void read_info_var(Section* scn);
    void read_info_fn(Section* scn);
    void read_info_cs(Section* scn);

    Section rodata;
    Section data;
    Section text;
    Dynamic dynamic;

    /* MV Sections */
    Section mvfn;
    Section mvvar;
    Section mvcs;
    DataSection mvdata;
    Section mvtext;

    std::vector<std::shared_ptr<MVVar>> vars;
    std::vector<std::unique_ptr<MVFn>> fns;
    std::vector<std::unique_ptr<MVPP>> pps;

    std::vector<GElf_Rela> rela_unmatched;
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
