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

    void load(Elf_Scn * s);
    std::string get_string(uint64_t addr);
    void fill(uint64_t addr, std::byte value, size_t len);
    void print(size_t elem_sz); // scn_in
    bool inside(uint64_t addr); // scn_in
    std::optional<GElf_Rela*> get_rela(uint64_t vaddr);
    virtual bool probe_rela(GElf_Rela *rela);
    void add_rela(uint64_t source, uint64_t target);
    bool in_segment(const GElf_Phdr &phdr);
    bool is_nobits();
    void set_scn_out(Elf_Scn *_scn_out) { scn_out = _scn_out;}

    constexpr size_t size()  { return sz; }
    constexpr size_t max_sz()  { return max_size; }
    std::byte* out_buf();
    std::byte* out_buf(uint64_t addr);
    const std::byte* in_buf();
    const std::byte* in_buf(uint64_t addr);
    void write_ptr(bool fpic, uint64_t address, uint64_t destination);

    virtual bool is_needed(bool overr);      // (in outfile)
    
    void set_out_scn(Elf_Scn *scn_out);

    std::vector<GElf_Rela> relocs;
    Elf_Scn * scn_in;
    Elf_Scn * scn_out = nullptr;
protected:
    size_t sz;
    uint64_t max_size;
};

class MVSection : public Section {
public:
    bool probe_rela(GElf_Rela *rela);

    uint64_t start_ptr;
    uint64_t stop_ptr;
protected:
    void add_data(MVData* );
};

class BssSection : public Section {
public:
    uint64_t generate(uint64_t offset, uint64_t vaddr_start, uint64_t vaddr_end);
    uint64_t old_sz();
    uint64_t new_sz();
};

class MVFnSection : public MVSection {
public:
    std::unique_ptr<std::vector<struct mv_info_fn>> read();
    uint64_t generate(bool fpic, uint64_t offset, uint64_t vaddr, Section *data);
    bool is_needed(bool overr);
    void set_fns(std::vector<std::unique_ptr<MVFn>> *fns);
private:
    std::vector<std::unique_ptr<MVFn>> *fns;
};

class MVVarSection : public MVSection {
public:
    std::unique_ptr<std::vector<struct mv_info_var>> read();
    uint64_t generate(bool fpic, uint64_t offset, uint64_t vaddr, Section *data);
    bool is_needed(bool overr);
    void set_vars(std::vector<std::shared_ptr<MVVar>> *vars);
private:
    std::vector<std::shared_ptr<MVVar>> *vars;
};

class MVCsSection : public MVSection {
public:
    std::unique_ptr<std::vector<struct mv_info_callsite>> read();
    uint64_t generate(bool fpic, uint64_t offset, uint64_t vaddr, Section *data);
    bool is_needed(bool overr);
    void set_pps(std::vector<std::unique_ptr<MVPP>> *pps);
private:
    std::vector<std::unique_ptr<MVPP>> *pps;
};

class MVDataSection : public MVSection {
public:
    uint64_t generate(bool fpic, uint64_t offset, uint64_t vaddr);
    bool is_needed(bool overr);
    void set_fns(std::vector<std::unique_ptr<MVFn>> *fns);
private:
    std::vector<std::unique_ptr<MVFn>> *fns;
};

class Dynamic : public Section {
public:
    void load(Elf_Scn *scn_in);
    void write();
    void print();
    std::optional<GElf_Dyn*> get_dyn(int64_t tag);
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

class Area {
public:
    Area(Elf *e_out, bool fpic);
    virtual ~Area() {}
    void set_phdr(GElf_Phdr &_phdr, const size_t &_ndx);
    virtual bool test_phdr(GElf_Phdr &phdr) = 0;
    virtual void find_start_of_area() = 0;
    virtual uint64_t size_in_file() = 0;

    constexpr bool not_found() { return !found; }
    constexpr uint64_t start_offset() { return area_offset_start; }
    constexpr uint64_t end_offset() { return area_offset_end; }
    constexpr uint64_t start_vaddr() { return area_vaddr_start; }
    constexpr uint64_t end_vaddr() { return area_vaddr_end; }
protected:
    bool found = false;
    GElf_Phdr phdr;
    size_t ndx;
    uint64_t area_offset_start;
    uint64_t area_offset_end;
    uint64_t area_vaddr_start;
    uint64_t area_vaddr_end;
    Elf *e_out;
    bool fpic;
};

class InfoArea : public Area {
public:
    InfoArea(Elf *e_out, bool fpic, MVDataSection *mvdata, MVVarSection *mvvar, 
            MVFnSection *mvfn, MVCsSection *mvcs, BssSection *bss);
    uint64_t generate(Section *data);
    void find_start_of_area();
    bool test_phdr(GElf_Phdr &phdr);
    uint64_t size_in_file();
    uint64_t shrink();
private:
    MVDataSection *mvdata;
    MVVarSection *mvvar;
    MVFnSection *mvfn;
    MVCsSection *mvcs;
    BssSection *bss;
};

class TextArea : public Area {
public:
    TextArea(Elf *e_out, bool fpic, Section *mvtext);
    uint64_t generate();
    void find_start_of_area();
    bool test_phdr(GElf_Phdr &phdr);
    uint64_t size_in_file();
private:
    Section *mvtext;
};

class Bintail {
public:
    Bintail(const char *infile);
    ~Bintail();

    void print(); // Display mv_info_* structs in __multiverse_* section
    void print_reloc();
    void print_sym();
    void print_dyn();
    void print_vars();

    void init_write(const char *outfile, bool del_scns);
    void write();
    void update_relocs_sym();

    void change(std::string change_str);
    void apply(std::string apply_str, bool guard);
    void apply_all(bool guard);

    std::unique_ptr<InfoArea> mvinfo_area;
    std::unique_ptr<TextArea> mvtext_area;

    Section rodata;
    Section text;

    /* editable */
    Section data;

    /* generable */
    BssSection bss;
    Dynamic dynamic;

    /* MV Sections */
    MVFnSection mvfn;
    MVVarSection mvvar;
    MVCsSection mvcs;
    MVDataSection mvdata;
    Section mvtext;

    std::vector<std::shared_ptr<MVVar>> vars;
    std::vector<std::unique_ptr<MVFn>> fns;
    std::vector<std::unique_ptr<MVPP>> pps;

    std::vector<GElf_Rela> rela_other;
    std::vector<symbol>  syms;
private:
    /* Elf file */
    int infd, outfd;
    Elf *e_in, *e_out;
    GElf_Ehdr ehdr_in, ehdr_out;

    Elf_Scn *reloc_scn_in;
    Elf_Scn *reloc_scn_out;

    Elf_Scn *symtab_scn;

    uint removed_scns;

    std::vector<struct sec> secs;
    std::map<Elf_Scn*, Section*> scn_handler;
};
#endif
