#include <iostream>
#include <algorithm>
#include <cassert>
#include <vector>
#include <string>
#include <cstdlib>
using namespace std;

#include "string.h"
#include "mvelem.h"
#include "bintail.h"

static const GElf_Rela make_rela(uint64_t source, uint64_t target) {
    GElf_Rela rela;
    rela.r_addend = target;
    rela.r_info = R_X86_64_RELATIVE;
    rela.r_offset = source;
    return rela;
}

//------------------MVText-----------------------------------
MVText::MVText(std::byte *buf, size_t size, uint64_t vaddr) {
    orig_vaddr = vaddr;
    copy(buf, buf+size, instr.begin());
}

size_t MVText::make_info(std::byte *buf, Section* scn, uint64_t vaddr) {
    copy(instr.cbegin(), instr.cend(), buf);
    // Adjust relocations
    for (auto& r : scn->relocs) {
        uint64_t orig_target = r.r_addend;
        uint64_t start = orig_vaddr;
        uint64_t end = start + instr.size();
        if (orig_target >= start && orig_target < end) {
            auto target = orig_target - start + vaddr;
            r.r_addend = target;
        }
    }
    return instr.size();
}

//------------------MVassign-----------------------------------
MVassign::MVassign(struct mv_info_assignment& _assign)
    :assign{_assign} { }

size_t MVassign::make_info(byte* buf, Section* sec, uint64_t vaddr) {
    auto ass =  reinterpret_cast<mv_info_assignment*>(buf);
    ass->variable.location = assign.variable.location;
    ass->lower_bound = assign.lower_bound;
    ass->upper_bound = assign.upper_bound;
    sec->relocs.push_back(make_rela(vaddr, ass->variable.location));
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

    mfn->function_body = mvfn.function_body;
    mfn->assignments = mvfn.assignments; // set by set_info_assigns
    mfn->n_assignments = assigns.size();
    mfn->type = mvfn.type;
    mfn->constant = mvfn.constant;

    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_mvfn, function_body), mvfn.function_body));
    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_mvfn, assignments), mvfn.assignments));
    return sizeof(mv_info_mvfn);
}

void MVmvfn::set_info_assigns(uint64_t vaddr) {
    mvfn.assignments = vaddr;
}

size_t MVmvfn::make_info_ass(std::byte* buf, Section* scn, uint64_t vaddr) {
    auto esz = 0ul;
    for (auto& a : assigns)
        esz += a->make_info(buf+esz, scn, vaddr+esz);
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

void MVmvfn::print(bool cur) {
    if (active())
        cout << ANSI_COLOR_YELLOW;

    if (cur)
        cout << " -> ";
    else
        cout << "    ";

    cout << "mvfn@0x" << hex << mvfn.function_body;

    auto type = mvfn.type == MVFN_TYPE_NONE ? "none" :
           mvfn.type == MVFN_TYPE_NOP ? "nop" :
           mvfn.type == MVFN_TYPE_CONSTANT ? "constant" :
           mvfn.type == MVFN_TYPE_CLI ? "cli" :
           mvfn.type == MVFN_TYPE_STI ? "sti" : "unknown";
    cout << " type=" << type;

    cout << "  -  assignments[] @0x" << hex
        << mvfn.assignments << "\n" ANSI_COLOR_RESET;
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
    f->name = fn.name;
    f->function_body = fn.function_body;
    f->n_mv_functions = mvfns.size();
    f->mv_functions = mvfn_vaddr;
    f->patchpoints_head = nullptr;

    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_fn, name), fn.name));
    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_fn, function_body), fn.function_body));
    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_fn, mv_functions), mvfn_vaddr));
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

void MVFn::print(Section* rodata, Section* text, Section* mvtext) {
    if (active == fn.function_body)
        cout << " -> ";
    else 
        cout << "    ";
    
    cout << rodata->get_string(fn.name) << " @0x" << hex << fn.function_body
        << "  -  mvfn[] @0x" << fn.mv_functions<< "\n";

    for (auto &mvfn : mvfns) {
        auto mact = active == mvfn->location();

        mvfn->print(mact);
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

void MVVar::print(Section* rodata, Section* text, Section* mvtext) {
    cout << "Var: " << rodata->get_string(var.name)
        << "@:0x" << location() << "\n";
    for (auto& fn : fns)
        fn->print(rodata, text, mvtext);
}

size_t MVVar::make_info(byte* buf, Section* sec, uint64_t vaddr) {
    auto v = reinterpret_cast<struct mv_info_var*>(buf);
    v->name = var.name;
    v->variable_location = var.variable_location;
    v->info = var.info;
    v->functions_head = nullptr;

    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_var, name), var.name));
    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_var, variable_location), var.variable_location));
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

//---------------------MVPP---------------------------------------------------
static int location_len(mv_info_patchpoint_type type) {
    if (type == PP_TYPE_X86_CALL_INDIRECT) {
        return 6;
    } else {
        return 5;
    }
}

//---------------------MVPP----------------------------------------------------
MVPP::MVPP(struct mv_info_callsite& cs, Section* text, Section* mvtext) {
    Section* txt;
    if (text->inside(cs.call_label))
        txt = text;
    else
        txt = mvtext;

    function_body = cs.function_body;

    decode_callsite(cs, txt);
    assert(!invalid());
}

size_t MVPP::make_info(byte* buf, Section* sec, uint64_t vaddr) {
    auto cs = reinterpret_cast<mv_info_callsite*>(buf);
    cs->function_body = function_body;
    cs->call_label = pp.location;

    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_callsite, function_body), function_body));
    sec->relocs.push_back(make_rela(vaddr+offsetof(struct mv_info_callsite, call_label), pp.location));
    return sizeof(mv_info_callsite);
}

MVPP::MVPP(MVFn* fn) : _fn{fn} {
    fptr = (fn->fn.n_mv_functions == 0);

    pp.type     = PP_TYPE_X86_JUMP;
    pp.location = fn->location();

    function_body = 0;

    assert(!invalid());
}

void MVPP::set_fn(MVFn* fn) {
    _fn = fn;
}

void MVPP::print(Section* text, Section* mvtext) {
    Section* txt;
    auto type = pp.type == PP_TYPE_INVALID ? "invalid" :
        pp.type == PP_TYPE_X86_CALL ? "call(x86)" :
        pp.type == PP_TYPE_X86_CALL_INDIRECT ? "indirect call(x86)" :
        pp.type == PP_TYPE_X86_JUMP ? "jump(x86)" : "nope";

    if (text->inside(pp.location)) {
        txt = text;
        cout << "\t\t@0x" << hex << pp.location << " Type:" << type;
    } else {
        txt = mvtext;
        cout << "\t\t@0x" << hex << pp.location << " Type:" << type;
    }

    if (fptr)
        cout << " <- fptr\n";
    else
        cout <<  "\n";
}

bool MVPP::invalid() { 
    return pp.type == PP_TYPE_INVALID;
}

uint64_t MVPP::decode_callsite(struct mv_info_callsite& cs, Section* text) {
    auto *p = text->get_func_loc(cs.call_label);
    uint64_t callee = 0;

    if (p[0] == 0xe8) { // normal call
        callee = cs.call_label + *(int*)(p + 1) + 5;
        pp.type = PP_TYPE_X86_CALL;
    } else if (p[0] == 0xff && p[1] == 0x15) { // indirect call (function ptr)
        callee = (uint64_t)(cs.call_label + *(int*)(p + 2) + 6);
        pp.type = PP_TYPE_X86_CALL_INDIRECT;
    } else
        pp.type = PP_TYPE_INVALID;

    pp.location = cs.call_label;
    return callee;
}

void MVPP::patchpoint_apply(struct mv_info_mvfn *mvfn, Section* text, Section* mvtext) {
    Section* txt;
    if (text->inside(pp.location))
        txt = text;
    else
        txt = mvtext;

    auto location = txt->get_func_loc(pp.location);
    uint32_t offset;

    switch(pp.type) {
        case PP_TYPE_X86_JUMP:
            location[0] = 0xe9; // jmp
            offset = (uintptr_t)mvfn->function_body - ((uintptr_t) pp.location + 5);
            *((uint32_t *)&location[1]) = offset;
            break;
        case PP_TYPE_X86_CALL:
        case PP_TYPE_X86_CALL_INDIRECT:
            // Oh, look. It has a very simple body!
            if (mvfn->type == MVFN_TYPE_NOP) {
                if (pp.type == PP_TYPE_X86_CALL_INDIRECT) {
                    memcpy(location, "\x66\x0F\x1F\x44\x00\x00", 6); // 6 byte NOP
                } else {
                    memcpy(location, "\x0F\x1F\x44\x00\x00", 5);     // 5 byte NOP
                }
            } else if (mvfn->type == MVFN_TYPE_CONSTANT) {
                location[0] = 0xb8; // mov $..., eax
                *(uint32_t *)(location + 1) = mvfn->constant;
                if (pp.type == PP_TYPE_X86_CALL_INDIRECT)
                    location[5] = '\x90'; // insert trailing NOP
            } else if (mvfn->type == MVFN_TYPE_CLI ||
                       mvfn->type == MVFN_TYPE_STI) {
                if (mvfn->type == MVFN_TYPE_CLI) {
                    location[0] = '\xfa'; // CLI
                } else {
                    location[0] = '\xfb'; // STI
                }
                if (pp.type == PP_TYPE_X86_CALL_INDIRECT) {
                    memcpy(&location[1], "\x0F\x1F\x44\x00\x00", 5); // 5 byte NOP
                } else {
                    memcpy(&location[1], "\x0F\x1F\x40\x00", 4);     // 4 byte NOP
                }
            } else {
                offset = (uintptr_t)mvfn->function_body - ((uintptr_t) pp.location + 5);
                location[0] = 0xe8; // call
                *((uint32_t *)&location[1]) = offset;
                if (pp.type == PP_TYPE_X86_CALL_INDIRECT)
                    location[5] = '\x90'; // insert trailing NOP
            }
            break;
        default:
            cerr << "Could not apply patchpoint: " 
                << hex << pp.location << endl;
            return;
    } 
    auto d = elf_getdata(txt->scn, nullptr);
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
}

void MVPP::patchpoint_revert() {
    auto location = (char*)(pp.location);
    int size = location_len(pp.type);
    // Revert to original state
    memcpy((void*)pp.location, &pp.swapspace[0], size);
    __builtin___clear_cache((char*)location, location+size);
}

void MVPP::patchpoint_size(void **from, void**to) {
    char* loc = (char*)(pp.location);
    *from = loc;
    *to = loc + location_len(pp.type);
}
