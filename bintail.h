#ifndef __BINTAIL_H
#define __BINTAIL_H

#include <vector>
#include <memory>
#include <map>
#include <string>
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
    bool inside(uint64_t addr);
    void set_size(uint64_t nsz);
    GElf_Rela* get_rela(uint64_t vaddr);

    void add_rela(GElf_Rela rela);

    size_t ndx()   { return elf_ndxscn(scn); }
    size_t vaddr() { return shdr.sh_addr; }
    uint64_t off() { return shdr.sh_offset; }
    size_t size()  { return sz; }
    uint8_t* buf() { return (uint8_t*)data->d_buf; }

    std::vector<GElf_Rela> relocs;
protected:
    Elf_Scn * scn;
    Elf_Data * data;
    Elf * elf;
    uint64_t get_data_offset(uint64_t addr);
    GElf_Shdr shdr;
    size_t sz;
    uint64_t max_size;
};

class Symbols : public Section {
public:
    void load(Elf* elf, Elf_Scn * s);
    void print_sym(Elf * elf, size_t shndx);
    size_t get_sym_val(std::string symbol);
private:
    std::vector<std::unique_ptr<GElf_Sym>> syms;
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

    /* Display hex view of raw multiverse sections */
    void print_mv_sections();

    /* Display mv_info_* structs in __multiverse_* section */
    void print();

    void load();
    void write();
    void trim();
    void trim_var();
    void trim_fn();
    void trim_cs();
    void trim_mvdata();
    void trim_mvtext();
    void update_relocs();

    void change(std::string change_str);
    void apply(std::string apply_str);
    void scatter_reloc(Elf_Scn* reloc_scn);

    void link_pp_fn();
    void add_fns();
    void print_vars();

    void read_info_var(Section* scn);
    void read_info_fn(Section* scn);
    void read_info_cs(Section* scn);

    Section rodata;
    Section data;
    Section text;
    Symbols symbols;

    /* MV Sections */
    Section mvfn;
    Section mvvar;
    Section mvcs;
    Section mvdata;
    Section mvtext;

    std::vector<std::shared_ptr<MVVar>> vars;
    std::vector<std::unique_ptr<MVFn>> fns;
    std::vector<std::unique_ptr<MVPP>> pps;

    std::vector<GElf_Rela> rela_unmatched;
    std::vector<GElf_Rela> rela_other;
private:
    /* Elf file */
    int fd;
    Elf* e;
    GElf_Ehdr ehdr;
    Elf_Scn * reloc_scn;

    size_t shstrndx;
    std::vector<struct sec> secs;
};
#endif
