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

size_t MVassign::make_info(byte* buf, Section* sec, uint64_t vaddr) {
    auto ass =  reinterpret_cast<mv_info_assignment*>(buf);
    GElf_Rela r_loc;

    ass->variable.location = assign.variable.location;
    r_loc.r_addend = ass->variable.location;
    r_loc.r_info = R_X86_64_RELATIVE;
    r_loc.r_offset = vaddr;
    sec->relocs.push_back(r_loc);

    ass->lower_bound = assign.lower_bound;
    ass->upper_bound = assign.upper_bound;

    return sizeof(mv_info_assignment);
}

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


MVmvfn::MVmvfn(struct mv_info_mvfn& _mvfn, Section* mvdata, Section* mvtext) {
    mvfn = _mvfn;
    decode_mvfn_body(&mvfn, mvtext->get_func_loc(mvfn.function_body));

    auto assign_array = static_cast<struct mv_info_assignment*>
        (mvdata->get_data_loc(mvfn.assignments));
    for (size_t x = 0; x < mvfn.n_assignments; x++) {
        auto assign = make_unique<MVassign>(assign_array[x]);
        assigns.push_back(move(assign));
    }
}

/* make mvfn & mvassings */
size_t MVmvfn::make_info(byte* buf, Section* sec, uint64_t vaddr) {
    auto mfn =  reinterpret_cast<mv_info_mvfn*>(buf);
    auto esz = 0ul;
    GElf_Rela r_assign, r_fbody;

    mfn->function_body = mvfn.function_body;
    r_fbody.r_addend = mfn->function_body;
    r_fbody.r_info = R_X86_64_RELATIVE;
    r_fbody.r_offset = vaddr;
    sec->relocs.push_back(r_fbody);

    mfn->n_assignments = assigns.size();

    mfn->type = mvfn.type;
    mfn->constant = mvfn.constant;

    esz += sizeof(mv_info_mvfn);

    mfn->assignments = mvfn.assignments; // set by set_info_assigns
    r_assign.r_addend = mfn->assignments;
    r_assign.r_info = R_X86_64_RELATIVE;
    r_assign.r_offset = vaddr+2*sizeof(uint64_t);
    sec->relocs.push_back(r_assign);

    return esz;
}

void MVmvfn::set_info_assigns(uint64_t vaddr) {
    mvfn.assignments = vaddr;
}


size_t MVmvfn::make_info_ass(std::byte* buf, Section* scn, uint64_t vaddr) {
    auto esz = 0ul;
    for (auto& a : assigns) {
        esz += a->make_info(buf+esz, scn, vaddr+esz);
    }
    return esz;
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

void MVmvfn::print(bool cur, Section* mvdata, Section* mvtext) {
    if (active())
        cout << ANSI_COLOR_YELLOW;

    if (cur)
        cout << " -> ";
    else
        cout << "    ";

    cout << "mvfn@.mvtext:0x" << hex << mvfn.function_body - mvtext->vaddr();

    auto type = mvfn.type == MVFN_TYPE_NONE ? "none" :
           mvfn.type == MVFN_TYPE_NOP ? "nop" :
           mvfn.type == MVFN_TYPE_CONSTANT ? "constant" :
           mvfn.type == MVFN_TYPE_CLI ? "cli" :
           mvfn.type == MVFN_TYPE_STI ? "sti" : "unknown";
    cout << " type=" << type;

    cout << "  -  assignments[] @.mvdata:0x" << hex
        << mvfn.assignments - mvdata->vaddr() << "\n" ANSI_COLOR_RESET;
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
void MVFn::apply(Section* text, Section* mvtext) {
    for (auto& e : mvfns) {
        if (e->active() && e->frozen()) {
            for (auto& p : pps) {
                p->patchpoint_apply(&e->mvfn, text, mvtext);
            }
            frozen = true;
        }
    }
}

void MVFn::set_mvfn_vaddr(uint64_t vaddr) {
    mvfn_vaddr = vaddr;
}

size_t MVFn::make_info(byte* buf, Section* sec, uint64_t vaddr) {
    auto f = reinterpret_cast<mv_info_fn*>(buf);
    GElf_Rela r_name, r_fbody, r_mvfns;
    
    f->name = fn.name;
    r_name.r_addend = f->name;
    r_name.r_info = R_X86_64_RELATIVE;
    r_name.r_offset = vaddr;
    sec->relocs.push_back(r_name);

    f->function_body = fn.function_body;
    r_fbody.r_addend = f->function_body;
    r_fbody.r_info = R_X86_64_RELATIVE;
    r_fbody.r_offset = vaddr+sizeof(uint64_t);
    sec->relocs.push_back(r_fbody);

    f->n_mv_functions = mvfns.size();

    f->mv_functions = mvfn_vaddr;
    r_mvfns.r_addend = mvfn_vaddr;
    r_mvfns.r_info = R_X86_64_RELATIVE;
    r_mvfns.r_offset = vaddr+3*sizeof(uint64_t);
    sec->relocs.push_back(r_mvfns);

    f->patchpoints_head = nullptr;
    return sizeof(mv_info_fn);
}


size_t MVFn::make_mvdata(std::byte* buf, Section* mvdata, uint64_t vaddr) {
    auto esz = 0ul;
    /*
     *        v-esz                                           v-asz
     * mvfn[3] assigns_mvfn0[] assigns_mvfn1[] assigns_mvfn2[]
     */
    auto asz = sizeof(mv_info_mvfn)*mvfns.size();

    for (auto& m : mvfns) {
        m->set_info_assigns(vaddr+asz);
        esz += m->make_info(buf+esz, mvdata, vaddr+esz);
        asz += m->make_info_ass(buf+asz, mvdata, vaddr+asz);
    }
    return asz;
}

bool MVFn::is_fixed() {
    return frozen;
}

void MVFn::add_pp(MVPP* pp) {
    if (pp->invalid())
        assert(false);
    pps.push_back(pp);
}

uint64_t MVFn::location() {
    return fn.function_body;
}

MVFn::MVFn(struct mv_info_fn& _fn, Section* mvdata, Section* mvtext)
    :frozen{false} {
    fn = _fn;

    if (fn.n_mv_functions == 0)
        return;

    auto mvfn_array = static_cast<struct mv_info_mvfn*>
        (mvdata->get_data_loc(fn.mv_functions));
    for (size_t j = 0; j < fn.n_mv_functions; j++) {
        auto mf = make_unique<MVmvfn>(mvfn_array[j], mvdata, mvtext);
        mvfns.push_back(move(mf));
    }
}

void MVFn::check_var(MVVar* var) {
    for (auto& mvfn : mvfns)
        mvfn->check_var(var, this);
}

void MVFn::print(Section* rodata, Section* mvdata, Section* text, Section* mvtext) {
    if (active == fn.function_body)
        cout << " -> ";
    else 
        cout << "    ";
    
    cout << rodata->get_string(fn.name) 
        << " @.mvtext:0x" << hex
        << fn.function_body - mvtext->vaddr()
        << "  -  mvfn[] @.mvdata:0x"
        << fn.mv_functions - mvdata->vaddr() << "\n";

    for (auto &mvfn : mvfns) {
        auto mact = active == mvfn->location();

        mvfn->print(mact, mvdata, mvtext);
    }
    
    cout << "\tpatchpoints:\n";
    for (auto& pp : pps)
        pp->print(text, mvtext);
    printf("\n");
}

//---------------------MVVar---------------------------------------------------
MVVar::MVVar(struct mv_info_var _var, Section* rodata, Section* data)
        :frozen{false}, var{_var} {
    _name += rodata->get_string(var.name);
    _value = data->get_value(var.variable_location);

    // Discard bytes > width
    auto b = var.variable_width * 8;
    _value -= (_value >> b) << b;
}

void MVVar::print(Section* rodata, Section* data, Section* text, Section* mvtext) {
    cout << "Var: " << rodata->get_string(var.name)
        << "@.data:0x" << location() - data->vaddr() << "\n";
    for (auto& fn : fns)
        fn->print(rodata, data, text, mvtext);
}

size_t MVVar::make_info(byte* buf, Section* sec, uint64_t vaddr) {
    auto v = reinterpret_cast<mv_info_var*>(buf);

    GElf_Rela r_name, r_vloc;
    
    v->name = var.name;
    r_name.r_addend = v->name;
    r_name.r_info = R_X86_64_RELATIVE;
    r_name.r_offset = vaddr;
    sec->relocs.push_back(r_name);

    v->variable_location = var.variable_location;
    r_vloc.r_addend = v->variable_location;
    r_vloc.r_info = R_X86_64_RELATIVE;
    r_vloc.r_offset = vaddr+sizeof(uint64_t);
    sec->relocs.push_back(r_vloc);

    v->info = var.info;
    v->functions_head = nullptr;
    return sizeof(struct mv_info_var);
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

void MVVar::apply(Section* text, Section* mvtext) {
    frozen = true;
    for (auto& e : fns)
        e->apply(text, mvtext);
}
