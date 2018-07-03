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

    virtual void load(Elf * elf, Elf_Scn * s);

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

    void add_rela(Elf_Data* d, uint64_t index, uint64_t vaddr);

    size_t ndx()   { return elf_ndxscn(scn); }
    size_t vaddr() { return shdr.sh_addr; }
    uint64_t off() { return shdr.sh_offset; }
    size_t size()  { return sz; }
    uint8_t* buf() { return (uint8_t*)data->d_buf; }

protected:
    Elf_Scn * scn;
    Elf_Data * data;
    Elf * elf;
    uint64_t get_data_offset(uint64_t addr);
    GElf_Shdr shdr;
    size_t sz;
    uint64_t max_size;

    Elf_Data * rela_data;
    std::map<uint64_t, uint64_t> rela_vaddr_ndx;
};

class Symbols : public Section {
public:
    void load(Elf* elf, Elf_Scn * s);
    void print_sym(Elf * elf, size_t shndx);
    size_t get_sym_val(std::string symbol);
private:
    std::vector<std::unique_ptr<GElf_Sym>> syms;
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
    void change(std::string change_str);
    void apply(std::string apply_str);
    void scatter_reloc(Elf_Scn* reloc_scn);

    void link_pp_fn();
    void add_fns();
    void print_vars();

    void read_info_var(Section* scn);
    void write_info_var(Symbols *syms, Section* data, std::vector<struct mv_info_var>* nlst);
    void read_info_fn(Section* scn);
    void write_info_fn(Symbols *syms, Section* data, std::vector<struct mv_info_fn>* nlst);
    void read_info_cs(Section* scn);
    void write_info_cs(Symbols *syms, Section* data, std::vector<struct mv_info_callsite>* nlst);

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
private:
    /* Elf file */
    int fd;
    Elf* e;
    GElf_Ehdr ehdr;

    size_t shstrndx;
};
#endif
