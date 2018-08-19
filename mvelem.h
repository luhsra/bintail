#ifndef __MVELEM_H
#define __MVELEM_H

#include <set>
#include <vector>
#include <memory>
#include <cstddef>
#include "bintail.h"

class MVFn;
class MVVar;
class MVPP;

class MVData {
public:
    virtual size_t make_info(std::byte* buf, Section* scn, uint64_t vaddr) = 0;
    virtual ~MVData() {}
};

//-----------------------------------------------------------------------------
class MVText : public MVData {
public:
    MVText(std::byte* buf, size_t size, uint64_t vaddr);
    size_t make_info(std::byte* buf, Section* scn, uint64_t vaddr);
private:
    long orig_vaddr;
    std::vector<std::byte> instr;
};

//-----------------------------------------------------------------------------
struct mv_info_assignment {
    uint64_t location;
    uint32_t lower_bound;
    uint32_t upper_bound;
};

class MVassign : public MVData {
public:
    MVassign(struct mv_info_assignment& _assign);
    size_t make_info(std::byte* buf, Section* scn, uint64_t vaddr);
    bool is_active();
    bool check_sym(const std::string &sym_match);
    void link_var(MVVar* _var);
    void print();

    constexpr uint64_t location() { return assign.location; }
    MVVar* var;
private:
    struct mv_info_assignment assign;
};

//-----------------------------------------------------------------------------
typedef enum : int { MVFN_TYPE_NONE, MVFN_TYPE_NOP, MVFN_TYPE_CONSTANT,
    MVFN_TYPE_CLI, MVFN_TYPE_STI } mvfn_type_t;

struct mv_info_mvfn {
    uint64_t function_body;      // A pointer to the mvfn's function body
    unsigned int n_assignments;  // The mvfn's variable assignments
    uint64_t assignments;        // Array of mv_info_assignment

    // runtime
    mvfn_type_t type; 
    uint32_t constant;
};

class MVmvfn : public MVData {
public:
    MVmvfn(struct mv_info_mvfn& _mvfn, DataSection* data, Section* text);
    size_t make_info(std::byte* buf, Section* scn, uint64_t vaddr);
    size_t make_info_ass(std::byte* buf, Section* scn, uint64_t vaddr);
    void set_info_assigns(uint64_t vaddr);
    void check_var(MVVar* var, MVFn* fn);
    void probe_sym(struct symbol &sym, const std::string &sym_match);
    void print(bool active);
    bool active();
    bool assign_vars_frozen();

    /* If a multiverse function body does nothing, or only returns a
     * constant value, we can further optimize the patched callsites. For a
     * dummy architecture implementation, this operation can be implemented
     * as a NOP. */
    void decode_mvfn_body(struct mv_info_mvfn *info, uint8_t * op);

    constexpr uint64_t location() { return mvfn.function_body; }
    constexpr size_t size() { return symbol.sym.st_size; }
    struct mv_info_mvfn mvfn;
private:
    std::vector<std::unique_ptr<MVassign>> assigns;
    struct symbol symbol;
};

//-----------------------------------------------------------------------------
struct mv_info_fn {
    uint64_t name;               // Functions's symbol name
    uint64_t function_body;      // A pointer to the original (generic) function body
    unsigned int n_mv_functions; // Specialized multiverse variant functions of this function
    uint64_t mv_functions;       // Array of mv_info_mvfn

    // runtime
    struct mv_patchpoint *patchpoints_head; // Patchpoints as linked list
    struct mv_info_mvfn *active_mvfn;       // The currently active mvfn
};

class MVFn : public MVData {
public:
    MVFn(struct mv_info_fn& _fn, DataSection* data, Section* text, Section* rodata);
    size_t make_info(std::byte* buf, Section* scn, uint64_t vaddr);
    void print();
    void probe_var(MVVar* var);
    void probe_sym(struct symbol &sym);
    void add_pp(MVPP* pp);
    void apply(Section* text, Section* mvtext, bool guard);
    size_t make_mvdata(std::byte* buf, DataSection* mvdata, uint64_t vaddr);
    void set_mvfn_vaddr(uint64_t vaddr);

    constexpr bool is_fixed() { return frozen; }
    constexpr uint64_t location() { return fn.function_body; }

    struct mv_info_fn fn;
    bool frozen;
    uint64_t active;
    uint64_t mvfn_vaddr;
private:
    std::vector<std::unique_ptr<MVmvfn>> mvfns;
    std::vector<MVPP*> pps;
    std::string name;
    struct symbol symbol;
};

//-----------------------------------------------------------------------------
struct mv_info_fn_ref {
    struct mv_info_fn_ref *next;
    struct mv_info_fn *fn;
};

struct mv_info_var {
    uint64_t name;
    uint64_t variable_location;         // A pointer to the variable
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

class MVVar : public MVData {
public:
    MVVar(struct mv_info_var _var, Section* rodata, Section* data);
    size_t make_info(std::byte* buf, Section* scn, uint64_t vaddr);
    void print();
    void link_fn(MVFn* fn);
    void set_value(int v, Section* data);
    void apply(Section* text, Section* mvtext, bool guard);
    uint64_t location();

    std::string& name() { return _name; }
    int64_t value() { return _value; }

    bool frozen;
    struct mv_info_var var;
private:
    std::set<MVFn*> fns;
    std::string _name;
    int64_t _value;
};

//-----------------------------------------------------------------------------
struct mv_info_callsite {
    uint64_t function_body;
    uint64_t call_label;
};

typedef enum  {
    PP_TYPE_INVALID,
    PP_TYPE_X86_CALL,
    PP_TYPE_X86_CALL_INDIRECT,
    PP_TYPE_X86_JUMP,
} mv_info_patchpoint_type;

struct mv_patchpoint {
    struct mv_patchpoint *next;
    uint64_t* function;
    uint64_t location;                // == callsite call_label
    mv_info_patchpoint_type type;
    unsigned char swapspace[6]; // Here we swap in the code, we overwrite
};

class MVPP : public MVData {
public:
    MVPP(MVFn* fn);
    MVPP(struct mv_info_callsite& cs, Section* text, Section* mvtext);
    void print();
    void set_fn(MVFn* fn);
    size_t make_info(std::byte* buf, Section* scn, uint64_t vaddr);
    uint64_t decode_callsite(struct mv_info_callsite& cs, Section* text); // ret callee
    void patchpoint_apply(struct mv_info_mvfn *mvfn, Section* text, Section* mvtext);
    void patchpoint_size(void **from, void** to);

    struct mv_patchpoint pp;
    uint64_t function_body;
    MVFn* _fn;
private:
    bool fptr;
};
#endif
