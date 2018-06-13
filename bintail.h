#ifndef __MVCTL_H
#define __MVCTL_H

#include <vector>
#include <iostream>
#include <iomanip>
#include <memory>
#include <list>
#include <string>
#include <gelf.h>
#include <set>

#include "arch.h"

using namespace std;

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

typedef uint64_t vaddr_cstr;
typedef uint64_t vaddr_text;
typedef uint64_t vaddr_data;

class MVFn;
//-----------------------------libmultiverse-header----------------------------
typedef enum  {
    PP_TYPE_INVALID,
    PP_TYPE_X86_CALL,
    PP_TYPE_X86_CALL_INDIRECT,
    PP_TYPE_X86_JUMP,
} mv_info_patchpoint_type;

struct mv_patchpoint {
    struct mv_patchpoint *next;
    MVFn* function;
    vaddr_text location;                // == callsite call_label
    mv_info_patchpoint_type type;

    // Here we swap in the code, we overwrite
    unsigned char swapspace[6];
};

struct mv_info_assignment {
    union {
        vaddr_data location;
        int info; // Runtime link
    } variable;
    uint32_t lower_bound;
    uint32_t upper_bound;
};

typedef enum {
    MVFN_TYPE_NONE,
    MVFN_TYPE_NOP,
    MVFN_TYPE_CONSTANT,
    MVFN_TYPE_CLI,
    MVFN_TYPE_STI,
} mvfn_type_t;

struct mv_info_mvfn {
    // static
    vaddr_text function_body;    // A pointer to the mvfn's function body
    unsigned int n_assignments;  // The mvfn's variable assignments
    vaddr_data assignments;      // Array of mv_info_assignment

    // runtime
    int type;                    // This is be interpreted as mv_type_t
                                 // (declared as integer to ensure correct size)
    uint32_t constant;
};

struct mv_info_fn {
    // static
    vaddr_cstr name;             // Functions's symbol name
    vaddr_text function_body;    // A pointer to the original (generic) function body
    unsigned int n_mv_functions; // Specialized multiverse variant functions of this function
    vaddr_data mv_functions;     // Array of mv_info_mvfn

    // runtime
    struct mv_patchpoint *patchpoints_head;  // Patchpoints as linked list TODO: arch-specific
    struct mv_info_mvfn *active_mvfn; // The currently active mvfn
};

struct mv_info_fn_ref {
    struct mv_info_fn_ref *next;
    struct mv_info_fn *fn;
};

struct mv_info_callsite {
    // static
    vaddr_text function_body;
    vaddr_text call_label;
};

struct mv_info_var {
    vaddr_cstr name;
    vaddr_data variable_location;         // A pointer to the variable
    union {
        unsigned int info;
        struct {
            unsigned int
                variable_width : 4,  // Width of the variable in bytes
                reserved       : 25, // Currently not used
                flag_tracked   : 1,  // Determines if the variable is tracked
                flag_signed    : 1,  // Determines if the variable is signed
                flag_bound     : 1;  // 1 if the variable is bound, 0 if not
                                     // -> this flag is mutable
        };
    };

    // runtime
    struct mv_info_fn_ref *functions_head; // Functions referening this variable
};
//--------------------------------multiverse.h---------------------------------
class Section {
public:
    Section() :sz{0} {}

    virtual void load(Elf * elf, Elf_Scn * s);

    string get_string(vaddr_cstr addr);
    uint8_t* get_func_loc(vaddr_text addr);
    void* get_data_loc(vaddr_data addr);
    uint64_t get_value(vaddr_data addr);
    void  set_data_int(vaddr_data addr, int value);
    void  set_data_ptr(vaddr_data addr, uint64_t value);
    void set_dirty();
    void add_fixed(uint64_t location) { fixed.push_back(location); }
    void print(size_t elem_sz);

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
    size_t get_sym_val(string symbol);
private:
    std::vector<unique_ptr<GElf_Sym>> syms;
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
class MVassign {
public:
    MVassign(struct mv_info_assignment& _assign);
    vaddr_data location();
    bool active();
    void link_var(MVVar* _var);
    void print();
    MVVar* var;
private:
    struct mv_info_assignment assign;
};

class MVFn;
class MVmvfn {
public:
    MVmvfn(struct mv_info_mvfn& _mvfn, Section* data, Section* text);
    void check_var(MVVar* var, MVFn* fn);
    void print(bool active, Section* data, Section* text);
    bool active();
    bool frozen();

    uint64_t location() { return mvfn.function_body; }
    struct mv_info_mvfn mvfn;
private:
    vector<unique_ptr<MVassign>> assigns;
};

class MVPP;
class MVFn {
public:
    MVFn(struct mv_info_fn& _fn, Section* data, Section* text);
    void print(Section* rodata, Section* data, Section* text);
    void check_var(MVVar* var);
    void add_cs(struct mv_info_callsite& cs, Section* text);
    vaddr_text location();
    void apply(Section* text);
    struct mv_info_fn fn;
    bool frozen;
    uint64_t active;
private:
    vector<unique_ptr<MVPP>> pps;
    vector<unique_ptr<MVmvfn>> mvfns;
};

class MVPP {
public:
    MVPP(MVFn* fn);
    MVPP(struct mv_info_callsite& cs, MVFn* fn, Section* text);
    bool invalid();
    void print(Section* text);
    struct mv_patchpoint pp;
private:
    bool fptr;
};

class MVVar {
public:
    MVVar(struct mv_info_var _var, Section* rodata, Section* data);
    void print(Section* rodata, Section* data, Section* text);
    void check_fns(vector<unique_ptr<MVFn>>& fns);
    void link_fn(MVFn* fn);
    void set_value(int v, Section* data);
    void apply(Section* text);
    vaddr_data location();

    string& name() { return _name; }
    int64_t value() { return _value; }

    bool frozen;
    struct mv_info_var var;
private:
    set<MVFn*> fns;
    string _name;
    int64_t _value;
};


class MVVars : public Section {
public:
    void load(Elf* elf, Elf_Scn * s);
    void parse(Section* rodata, Section* data);
    void print(Section* rodata, Section* data, Section* text);
    void add_cs(CsSection* mvcs, Section* text);
    void add_fns(FnSection* mvfn, Section* data, Section* text);
    void set_var(string var_name, int v, Section* data);
    void apply_var(string var_name, Section* text);
    void mark_fixed(FnSection* fn_sec, CsSection* cs_sec);
    void regenerate(Symbols* syms, Section* data);

    std::vector<struct mv_info_var> lst;
private:
    void parse_assigns();

    vector<shared_ptr<MVVar>> vars;
    vector<unique_ptr<MVFn>> fns;
};

class MVCTL {
public:
    MVCTL(string filename);
    ~MVCTL();

    void print_reloc();
    void print_sym();

    /* Display hex view of raw multiverse sections */
    void print_mv_sections();

    /* Display mv_info_* structs in __multiverse_* section */
    void print();

    void load();
    void write();
    void trim();
    void change(string change_str);
    void apply(string apply_str);

    Section rodata;
    Section data;
    Section text;
    Symbols symbols;

    /* MV Sections */
    FnSection mvfn;
    MVVars mvvar;
    CsSection mvcs;

private:
    /* Elf file */
    int fd;
    Elf* e;
    GElf_Ehdr ehdr;

    size_t shstrndx;
};
#endif
