#include <iostream>
#include <algorithm>
#include <cassert>
#include <vector>
#include <string>
using namespace std;

#include "arch.h"
#include "bintail.h"

//------------------MVassign-----------------------------------
MVassign::MVassign(struct mv_info_assignment& _assign)
    :assign{_assign}
{
}

vaddr_data MVassign::location()
{
    return assign.variable.location;
}

void MVassign::link_var(MVVar* _var)
{
    var = _var;
}

bool MVassign::active()
{
    auto low = assign.lower_bound;
    auto high = assign.upper_bound;
    auto val = var->value();

    return val >= low && val <= high;
}

void MVassign::print()
{
    auto name = var->name();
    auto value = var->value();

    if (active()) cout << ANSI_COLOR_GREEN;
    
    cout << "\t\t" << dec << assign.lower_bound << " <= " << name << "(" << value << ")" 
        << " <= " << assign.upper_bound << "\n" ANSI_COLOR_RESET;
}

//---------------------MVmvfn--------------------------------------------------
MVmvfn::MVmvfn(struct mv_info_mvfn& _mvfn, Section* data, Section* text)
{
    mvfn = _mvfn;

    multiverse_arch_decode_mvfn_body(&mvfn,
            text->get_func_loc(mvfn.function_body));

    auto assign_array = static_cast<struct mv_info_assignment*>
        (data->get_data_loc(mvfn.assignments));
    for (size_t x = 0; x < mvfn.n_assignments; x++) {
        auto assign = make_unique<MVassign>(assign_array[x]);
        assigns.push_back(move(assign));
    }
}

bool MVmvfn::active()
{
    for (auto& assign : assigns)
        if (!assign->active())
            return false;
    return true;
}

bool MVmvfn::frozen()
{
    for (auto& e : assigns)
        if (e->var->frozen == false)
            return false;
    return true;
}

void MVmvfn::print(bool cur, Section* data, Section* text)
{
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

void MVmvfn::check_var(MVVar* var, MVFn* fn)
{
    for (auto& assign : assigns) {
        if (var->location() == assign->location()) {
            assign->link_var(var);
            var->link_fn(fn);
        }
    }
}

//---------------------MVFn----------------------------------------------------
void MVFn::apply(Section* text)
{
    for (auto& e : mvfns) {
        if (e->active() && e->frozen()) {
            for (auto& p : pps) {
                multiverse_arch_patchpoint_apply(&e->mvfn, &p->pp, text);
            }
            frozen = true;
        }
    }
}

void MVFn::add_cs(struct mv_info_callsite& cs, Section* text)
{
    auto pp = make_unique<MVPP>(cs, this, text);
    pps.push_back(move(pp));
}

vaddr_text MVFn::location()
{
    return fn.function_body;
}

MVFn::MVFn(struct mv_info_fn& _fn, Section* data, Section* text)
    :frozen{false}
{
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

void MVFn::check_var(MVVar* var)
{
    for (auto& mvfn : mvfns)
        mvfn->check_var(var, this);
}

void MVFn::print(Section* rodata, Section* data, Section* text)
{
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
MVPP::MVPP(struct mv_info_callsite& cs, MVFn* fn, Section* text)
{
    multiverse_arch_decode_callsite(fn, cs, &pp, text);
    assert(!invalid());
}

MVPP::MVPP(MVFn* fn)
{
    fptr = (fn->fn.n_mv_functions == 0);
    multiverse_arch_decode_function(fn, &pp);
    assert(!invalid());
}

void MVPP::print(Section* text)
{
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

bool MVPP::invalid()
{ 
    return pp.type == PP_TYPE_INVALID;
}

//---------------------MVVar---------------------------------------------------
MVVar::MVVar(struct mv_info_var _var, Section* rodata, Section* data)
        :frozen{false}, var{_var}
{
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

void MVVar::print(Section* rodata, Section* data, Section* text)
{
    cout << "Var: " << rodata->get_string(var.name)
        << "@.data:0x" << location() - data->vaddr() << "\n";
    for (auto& fn : fns) {
        fn->print(rodata, data, text);
    }
}

void MVVar::link_fn(MVFn* fn)
{
    fns.insert(fn);
}

void MVVar::set_value(int v, Section* data)
{
    _value = v;
    assert(var.variable_width == 4); 
    data->set_data_int(var.variable_location, v);
}

vaddr_data MVVar::location()
{
    return var.variable_location;
}

void MVVar::check_fns(vector<unique_ptr<MVFn>>& fns)
{
    for (auto& fn : fns)
        fn->check_var(this);
}

void MVVar::apply(Section* text)
{
    frozen = true;
    for (auto& e : fns)
        e->apply(text);
}

//---------------------MVVars--------------------------------------------------
void MVVars::regenerate(Symbols *syms, Section* data) {
    vector<struct mv_info_var> nlst;

    for (auto& e:vars) {
        if (e->frozen)
            continue;
        nlst.push_back(e->var);
    }

    auto d = elf_getdata(scn, nullptr);
    auto buf = (struct mv_info_var*)d->d_buf;
    copy(nlst.begin(), nlst.end(), buf);

    auto size = nlst.size()*sizeof(struct mv_info_var);

    auto sym = syms->get_sym_val("__stop___multiverse_var_ptr"s);
    uint64_t sec_end_old = data->get_value(sym);
    uint64_t sec_end_new = sec_end_old - shdr.sh_size + size;

    data->set_data_ptr(sym, sec_end_new);
    d->d_size = size;
    shdr.sh_size = size;
    set_dirty();
}

void MVVars::mark_fixed(FnSection* fn_sec, CsSection* cs_sec) {
    for (auto& f : fns) {
        if (f->frozen) {
            fn_sec->add_fixed(f->location());
            cs_sec->add_fixed(f->location());
        }
    }
    for (auto& v : vars) {
        if (v->frozen) {
            add_fixed(v->location());
        }
    }
}

void MVVars::parse_assigns()
{
    /**
     * find var & save ptr to it
     *    add fn to var.functions_head
     */
    for (auto& var: vars) {
        var->check_fns(fns);
    }
}

/**
 * For all callsites:
 * 1. Find function
 * 2. Create patchpoint
 * 3. Append pp to fn ll
 */
void MVVars::add_cs(CsSection* mvcs, Section* text)
{
    for (auto& cs : mvcs->lst) {
        for (auto& fn : fns) {
            if (fn->location() != cs.function_body )
                continue;

            fn->add_cs(cs, text);
        }
    }
}

void MVVars::add_fns(FnSection* mvfn, Section* data, Section* text)
{
    for (auto& fn : mvfn->lst) {
        auto f = make_unique<MVFn>(fn, data, text);
        fns.push_back(move(f));
    }

    parse_assigns();
}

void MVVars::load(Elf* e, Elf_Scn * s)
{
    elf = e;
    scn = s;
    gelf_getshdr(s, &shdr);

    Elf_Data * d = nullptr;
    while ((d = elf_getdata(scn, d)) != nullptr) {
        for (auto i = 0; i * sizeof(struct mv_info_var) < d->d_size; i++) {
            lst.push_back(*((struct mv_info_var*)d->d_buf + i));
            sz++;
        }
    }
}

void MVVars::parse(Section* rodata, Section* data)
{
    for (auto& e : lst) {
        auto var = make_unique<MVVar>(e, rodata, data);
        vars.push_back(move(var));
    }
}

void MVVars::apply_var(string var_name, Section* text)
{
    for (auto& e : vars) {
        if (var_name == e->name())
            e->apply(text);
    }
}

void MVVars::set_var(string var_name, int v, Section* data)
{
    for (auto& e : vars) {
        if (var_name == e->name())
            e->set_value(v, data);
    }
}

void MVVars::print(Section* rodata, Section* data, Section* text)
{
    for (auto& var : vars)
        var->print(rodata, data, text);
}
