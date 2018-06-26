#ifndef __BINTAIL_H
#define __BINTAIL_H

#include <vector>
#include <memory>
#include <string>
#include <gelf.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

class Section {
public:
    Section() :sz{0} {}

    virtual void load(Elf * elf, Elf_Scn * s);

    std::string get_string(uint64_t addr);
    uint8_t* get_func_loc(uint64_t addr);
    void* get_data_loc(uint64_t addr);
    uint64_t get_value(uint64_t addr);
    void  set_data_int(uint64_t addr, int value);
    void  set_data_ptr(uint64_t addr, uint64_t value);
    void set_dirty();
    void add_fixed(uint64_t location) { fixed.push_back(location); }
    void print(size_t elem_sz);
    bool inside(uint64_t addr);

    size_t ndx()   { return elf_ndxscn(scn); }
    size_t vaddr() { return shdr.sh_addr; }
    uint64_t off() { return shdr.sh_offset; }
    size_t size()  { return sz; }
protected:
    Elf_Scn * scn;
    Elf * elf;
    std::vector<uint64_t> fixed;
    uint64_t get_data_offset(uint64_t addr);
    GElf_Shdr shdr;
    size_t sz;
};

class Symbols : public Section {
public:
    void load(Elf* elf, Elf_Scn * s);
    void print_sym(Elf * elf, size_t shndx);
    size_t get_sym_val(std::string symbol);
private:
    std::vector<std::unique_ptr<GElf_Sym>> syms;
};

class FnSection : public Section {
public:
    void load(Elf* elf, Elf_Scn * s);
    void regenerate(Symbols* syms, Section* data);
    std::vector<struct mv_info_fn> lst;
};

class CsSection : public Section {
public:
    void regenerate(Symbols* syms, Section* data);
    void load(Elf* elf, Elf_Scn * s);
    std::vector<struct mv_info_callsite> lst;
};

class MVVar;
class MVFn;
class VarSection : public Section {
public:
    void load(Elf* elf, Elf_Scn * s);
    void parse(Section* rodata, Section* data);
    void print(Section* rodata, Section* data, Section* text, Section* mvtext);
    void add_cs(CsSection* mvcs, Section* text, Section* mvtext);
    void add_fns(FnSection* mvfn, Section* data, Section* text);
    void set_var(std::string var_name, int v, Section* data);
    void apply_var(std::string var_name, Section* text, Section* mvtext);
    void mark_fixed(FnSection* fn_sec, CsSection* cs_sec);
    void regenerate(Symbols* syms, Section* data);

    std::vector<struct mv_info_var> lst;
private:
    void parse_assigns();

    std::vector<std::shared_ptr<MVVar>> vars;
    std::vector<std::unique_ptr<MVFn>> fns;
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

    Section rodata;
    Section data;
    Section text;
    Symbols symbols;

    /* MV Sections */
    FnSection mvfn;
    VarSection mvvar;
    CsSection mvcs;
    Section mvdata;
    Section mvtext;

private:
    /* Elf file */
    int fd;
    Elf* e;
    GElf_Ehdr ehdr;

    size_t shstrndx;
};
#endif
