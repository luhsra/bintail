#include <iostream>
#include <algorithm>
#include <cassert>
#include <vector>
#include <string>
#include <cstdlib>
using namespace std;

#include "mvpp.h"
#include "bintail.h"

//------------------MVassign-----------------------------------
MVassign::MVassign(struct mv_info_assignment& _assign)
    :assign{_assign} { }

uint64_t MVassign::location() {
    return assign.variable.location;
}

void MVassign::link_var(MVVar* _var) {
    var = _var;
}

bool MVassign::active() {
    auto low = assign.lower_bound;
    auto high = assign.upper_bound;
    auto val = var->value();

    return val >= low && val <= high;
}

void MVassign::print() {
    auto name = var->name();
    auto value = var->value();

    if (active()) cout << ANSI_COLOR_GREEN;
    
    cout << "\t\t" << dec << assign.lower_bound << " <= " << name << "(" << value << ")" 
        << " <= " << assign.upper_bound << "\n" ANSI_COLOR_RESET;
}

//---------------------MVmvfn--------------------------------------------------
static int is_ret(uint8_t* addr) {
    //    c3: retq
    // f3 c3: repz retq
    return addr[0] == 0xc3 || (addr[0] == 0xf3 && addr[1] == 0xc3);
}

void MVmvfn::decode_mvfn_body(struct mv_info_mvfn *info, uint8_t * op) {
    // 31 c0: xor    %eax,%eax
    //    c3: retq
    if ((op[0] == 0x31 && op[1] == 0xc0) && is_ret(op + 2)) {
        // multiverse_os_print("eax = 0\n");
        info->type = MVFN_TYPE_CONSTANT;
        info->constant = 0;
    } else if (op[0] == 0xb8 && is_ret(op + 5)) {
        info->type = MVFN_TYPE_CONSTANT;
        info->constant = *(uint32_t *)(op +1);
        // multiverse_os_print("eax = %d\n", info->constant);
    } else if (is_ret(op)) {
        // multiverse_os_print("NOP\n");
        info->type = MVFN_TYPE_NOP;
    } else if (op[0] == 0xfa && is_ret(op + 1)) {
        info->type = MVFN_TYPE_CLI;
    } else if (op[0] == 0xfb&& is_ret(op + 1)) {
        info->type = MVFN_TYPE_STI;
    } else {
        info->type = MVFN_TYPE_NONE;
    }
}


MVmvfn::MVmvfn(struct mv_info_mvfn& _mvfn, Section* data, Section* text) {
    mvfn = _mvfn;

    decode_mvfn_body(&mvfn,
            text->get_func_loc(mvfn.function_body));

    auto assign_array = static_cast<struct mv_info_assignment*>
        (data->get_data_loc(mvfn.assignments));
    for (size_t x = 0; x < mvfn.n_assignments; x++) {
        auto assign = make_unique<MVassign>(assign_array[x]);
        assigns.push_back(move(assign));
    }
}

bool MVmvfn::active() {
    for (auto& assign : assigns)
        if (!assign->active())
            return false;
    return true;
}

bool MVmvfn::frozen() {
    for (auto& e : assigns)
        if (e->var->frozen == false)
            return false;
    return true;
}

void MVmvfn::print(bool cur, Section* data, Section* text) {
    if (active())
        cout << ANSI_COLOR_YELLOW;

    if (cur)
        cout << " -> ";
    else
        cout << "    ";

    cout << "mvfn@.text:0x" << hex << mvfn.function_body - text->vaddr();

    auto type = mvfn.type == MVFN_TYPE_NONE ? "none" :
           mvfn.type == MVFN_TYPE_NOP ? "nop" :
           mvfn.type == MVFN_TYPE_CONSTANT ? "constant" :
           mvfn.type == MVFN_TYPE_CLI ? "cli" :
           mvfn.type == MVFN_TYPE_STI ? "sti" : "unknown";
    cout << " type=" << type;

    cout << "  -  assignments[] @.data:0x" << hex
        << mvfn.assignments - data->vaddr() << "\n" ANSI_COLOR_RESET;
    for (auto& assign : assigns)
        assign->print();
}

void MVmvfn::check_var(MVVar* var, MVFn* fn) {
    for (auto& assign : assigns) {
        if (var->location() == assign->location()) {
            assign->link_var(var);
            var->link_fn(fn);
        }
    }
}

//---------------------MVFn----------------------------------------------------
void MVFn::apply(Section* text) {
    for (auto& e : mvfns) {
        if (e->active() && e->frozen()) {
            for (auto& p : pps) {
                p->patchpoint_apply(&e->mvfn, text);
            }
            frozen = true;
        }
    }
}

void MVFn::add_cs(struct mv_info_callsite& cs, Section* text) {
    auto pp = make_unique<MVPP>(cs, this, text);
    pps.push_back(move(pp));
}

uint64_t MVFn::location() {
    return fn.function_body;
}

MVFn::MVFn(struct mv_info_fn& _fn, Section* data, Section* text)
    :frozen{false} {
    fn = _fn;

    auto pp = make_unique<MVPP>(this);
    if (pp->invalid())
        assert(false);
    pps.push_back(move(pp));

    if (fn.n_mv_functions == 0)
        return;

    auto mvfn_array = static_cast<struct mv_info_mvfn*>
        (data->get_data_loc(fn.mv_functions));
    for (size_t j = 0; j < fn.n_mv_functions; j++) {
        auto mf = make_unique<MVmvfn>(mvfn_array[j], data, text);
        mvfns.push_back(move(mf));
    }
}

void MVFn::check_var(MVVar* var) {
    for (auto& mvfn : mvfns)
        mvfn->check_var(var, this);
}

void MVFn::print(Section* rodata, Section* data, Section* text) {
    if (active == fn.function_body)
        cout << " -> ";
    else 
        cout << "    ";
    
    cout << rodata->get_string(fn.name) 
        << " @.text:0x" << hex
        << fn.function_body - text->vaddr()
        << "  -  mvfn[] @.data:0x"
        << fn.mv_functions - data->vaddr() << "\n";

    for (auto &mvfn : mvfns) {
        auto mact = active == mvfn->location();

        mvfn->print(mact, data, text);
    }
    
    cout << "\tpatchpoints:\n";
    for (auto& pp : pps)
        pp->print(text);
    printf("\n");
}

//---------------------MVPP----------------------------------------------------
MVPP::MVPP(struct mv_info_callsite& cs, MVFn* fn, Section* text) {
    decode_callsite(fn, cs, text);
    assert(!invalid());
}

MVPP::MVPP(MVFn* fn) {
    fptr = (fn->fn.n_mv_functions == 0);
    decode_function(fn);
    assert(!invalid());
}

void MVPP::print(Section* text) {
    auto type = pp.type == PP_TYPE_INVALID ? "invalid" :
        pp.type == PP_TYPE_X86_CALL ? "call(x86)" :
        pp.type == PP_TYPE_X86_CALL_INDIRECT ? "indirect call(x86)" :
        pp.type == PP_TYPE_X86_JUMP ? "jump(x86)" : "nope";

    cout << "\t\t@.text:0x" << hex << pp.location - text->vaddr() << " Type:" << type;

    if (fptr)
        cout << " <- fptr\n";
    else
        cout <<  "\n";
}

bool MVPP::invalid() { 
    return pp.type == PP_TYPE_INVALID;
}

//---------------------MVVar---------------------------------------------------
MVVar::MVVar(struct mv_info_var _var, Section* rodata, Section* data)
        :frozen{false}, var{_var} {
    _name += rodata->get_string(var.name);

    assert(!var.flag_signed);

    auto vptr = data->get_data_loc(var.variable_location);

    if (var.variable_width == 1)
        _value = static_cast<uint64_t>(*(static_cast<uint8_t*>(vptr)));
    else if (var.variable_width == 2)
        _value = static_cast<uint64_t>(*(static_cast<uint16_t*>(vptr)));
    else if (var.variable_width == 4)
        _value = static_cast<uint64_t>(*(static_cast<uint32_t*>(vptr)));
    else if (var.variable_width == 8)
        _value = static_cast<uint64_t>(*(static_cast<uint64_t*>(vptr)));
    else
        assert(false);
}

void MVVar::print(Section* rodata, Section* data, Section* text) {
    cout << "Var: " << rodata->get_string(var.name)
        << "@.data:0x" << location() - data->vaddr() << "\n";
    for (auto& fn : fns) {
        fn->print(rodata, data, text);
    }
}

void MVVar::link_fn(MVFn* fn) {
    fns.insert(fn);
}

void MVVar::set_value(int v, Section* data) {
    _value = v;
    assert(var.variable_width == 4); 
    data->set_data_int(var.variable_location, v);
}

uint64_t MVVar::location() {
    return var.variable_location;
}

void MVVar::check_fns(vector<unique_ptr<MVFn>>& fns) {
    for (auto& fn : fns)
        fn->check_var(this);
}

void MVVar::apply(Section* text) {
    frozen = true;
    for (auto& e : fns)
        e->apply(text);
}
