#include <iostream>
#include <algorithm>
#include <cassert>
#include <vector>
#include <string>
#include <cstdlib>
#include <regex>
using namespace std;

#include "string.h"
#include "mvelem.h"
#include "bintail.h"

//------------------MVText-----------------------------------
MVText::MVText(std::byte *buf, size_t size, uint64_t vaddr) {
    orig_vaddr = vaddr;
    copy(buf, buf+size, instr.begin());
}

size_t MVText::make_info(bool fpic, std::byte *buf, Section* scn, uint64_t vaddr) {
    copy(instr.cbegin(), instr.cend(), buf);
    if (fpic) {
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
    }
    return instr.size();
}

//------------------MVassign-----------------------------------
MVassign::MVassign(struct mv_info_assignment& _assign)
    :assign{_assign} { }

size_t MVassign::make_info(bool fpic, byte* buf, Section* sec, uint64_t vaddr) {
    auto ass =  reinterpret_cast<mv_info_assignment*>(buf);
    ass->location = assign.location;
    ass->lower_bound = assign.lower_bound;
    ass->upper_bound = assign.upper_bound;
    if (fpic) {
        sec->add_rela(vaddr, ass->location);
    }
    return sizeof(mv_info_assignment);
}
void MVassign::link_var(MVVar* _var) {
    var = _var;
}

bool MVassign::check_sym(const string &sym_match) {
    smatch m;
    regex pat { var->name() + "_" + (var->value() ? "(1|true)" : "(0|false)") + "(\\.|$)"};
    return regex_search(sym_match, m, pat);
}

bool MVassign::is_active() {
    auto low = assign.lower_bound;
    auto high = assign.upper_bound;
    auto val = var->value();
    return val >= low && val <= high;
}

void MVassign::print() {
    cout << (is_active() ? ANSI_COLOR_GREEN : "" ) << "\t\t" 
         << dec << assign.lower_bound << " <= " 
         << var->name() << "(" << var->value() << ")" 
         << " <= " << assign.upper_bound << "\n" ANSI_COLOR_RESET;
}

//---------------------MVmvfn--------------------------------------------------
static bool is_ret(const uint8_t* addr) {
    //    c3: retq
    // f3 c3: repz retq
    return addr[0] == 0xc3 || (addr[0] == 0xf3 && addr[1] == 0xc3);
}

MVmvfn::MVmvfn(struct mv_info_mvfn& _mvfn, MVDataSection* mvdata, Section* mvtext) {
    mvfn = _mvfn;
    auto op = reinterpret_cast<const uint8_t*>(mvtext->in_buf(mvfn.function_body));
    // 31 c0: xor    %eax,%eax
    if ((op[0] == 0x31 && op[1] == 0xc0) && is_ret(op + 2)) {
        mvfn.type = MVFN_TYPE_CONSTANT;
        mvfn.constant = 0;
    } else if (op[0] == 0xb8 && is_ret(op + 5)) {
        mvfn.type = MVFN_TYPE_CONSTANT;
        mvfn.constant = *(uint32_t *)(op +1);
    } else if (is_ret(op)) {
        mvfn.type = MVFN_TYPE_NOP;
    } else if (op[0] == 0xfa && is_ret(op + 1)) {
        mvfn.type = MVFN_TYPE_CLI;
    } else if (op[0] == 0xfb&& is_ret(op + 1)) {
        mvfn.type = MVFN_TYPE_STI;
    } else {
        mvfn.type = MVFN_TYPE_NONE;
    }
    auto assign_infos = reinterpret_cast<const struct mv_info_assignment*>
        (mvdata->in_buf(mvfn.assignments));
    for_each(assign_infos, assign_infos+mvfn.n_assignments, [&](auto ainfo)
            { assigns.push_back(make_unique<MVassign>(ainfo)); });
}

/* make mvfn & mvassings */
size_t MVmvfn::make_info(bool fpic, byte* buf, Section* sec, uint64_t vaddr) {
    auto mfn =  reinterpret_cast<mv_info_mvfn*>(buf);

    mfn->function_body = mvfn.function_body;
    mfn->assignments = mvfn.assignments; // set by set_info_assigns
    mfn->n_assignments = assigns.size();
    mfn->type = mvfn.type;
    mfn->constant = mvfn.constant;

    if (fpic) {
        sec->add_rela(vaddr+offsetof(struct mv_info_mvfn, function_body), mvfn.function_body);
        sec->add_rela(vaddr+offsetof(struct mv_info_mvfn, assignments), mvfn.assignments);
    }
    return sizeof(mv_info_mvfn);
}

void MVmvfn::set_info_assigns(uint64_t vaddr) {
    mvfn.assignments = vaddr;
}

size_t MVmvfn::make_info_ass(bool fpic, std::byte* buf, Section* scn, uint64_t vaddr) {
    auto esz = 0ul;
    for (auto& a : assigns)
        esz += a->make_info(fpic, buf+esz, scn, vaddr+esz);
    return esz;
}

bool MVmvfn::active() {
    return all_of(assigns.cbegin(), assigns.cend(), [](auto& a)
            { return a->is_active(); });
}

bool MVmvfn::assign_vars_frozen() {
    return all_of(assigns.cbegin(), assigns.cend(), [](auto &a)
            { return a->var->frozen; });
}

void MVmvfn::print(bool cur) {
    auto type = mvfn.type == MVFN_TYPE_NONE ? "none" :
           mvfn.type == MVFN_TYPE_NOP ? "nop" :
           mvfn.type == MVFN_TYPE_CONSTANT ? "constant" :
           mvfn.type == MVFN_TYPE_CLI ? "cli" :
           mvfn.type == MVFN_TYPE_STI ? "sti" : "unknown";
    cout << (active() ? ANSI_COLOR_YELLOW : "")
         << (cur ?  " -> " : "    ")
         << "mvfn@0x" << hex << mvfn.function_body << ":0x" << symbol.sym.st_size
         << " type=" << type
         << "  -  assignments[] @0x" << hex
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

void MVmvfn::probe_sym(struct symbol &sym, const string &sym_match) {
    if (all_of(assigns.begin(), assigns.end(), [&](auto& ass)
                { return ass->check_sym(sym_match); }))
        symbol = sym;

}

//---------------------MVFn----------------------------------------------------
void MVFn::apply(Section* text, Section* mvtext, bool guard) {
    auto pfn = find_if(mvfns.begin(), mvfns.end(), [](auto& mfn)
            { return mfn->assign_vars_frozen() && mfn->active(); });
    if (pfn == mvfns.end())
        return;
    if (guard) {
        for (auto& e : mvfns)
            if (e.get() != pfn.base()->get())
                mvtext->fill(e->location(), byte{0xcc}, e->size());
        mvtext->fill(location(), byte{0xcc}, symbol.sym.st_size); // overriden by pp
    }
    for (auto& p : pps) 
        p->patchpoint_apply(&(pfn->get()->mvfn), text, mvtext);
    frozen = true;
}

void MVFn::set_mvfn_vaddr(uint64_t vaddr) {
    mvfn_vaddr = vaddr;
}

size_t MVFn::make_info(bool fpic, byte* buf, Section* sec, uint64_t vaddr) {
    auto f = reinterpret_cast<mv_info_fn*>(buf);
    f->name = fn.name;
    f->function_body = fn.function_body;
    f->n_mv_functions = mvfns.size();
    f->mv_functions = mvfn_vaddr;
    f->patchpoints_head = nullptr;

    if (fpic) {
        sec->add_rela(vaddr+offsetof(struct mv_info_fn, name), fn.name);
        sec->add_rela(vaddr+offsetof(struct mv_info_fn, function_body), fn.function_body);
        sec->add_rela(vaddr+offsetof(struct mv_info_fn, mv_functions), mvfn_vaddr);
    }
    return sizeof(mv_info_fn);
}

size_t MVFn::make_mvdata(bool fpic, std::byte* buf, MVDataSection *mvdata, uint64_t vaddr) {
    /*        v-esz                                           v-asz
     * mvfn[3] assigns_mvfn0[] assigns_mvfn1[] assigns_mvfn2[]
     */
    auto esz = 0ul;
    auto asz = sizeof(mv_info_mvfn)*mvfns.size();
    for (auto& m : mvfns) {
        m->set_info_assigns(vaddr+asz);
        esz += m->make_info(fpic, buf+esz, mvdata, vaddr+esz);
        asz += m->make_info_ass(fpic, buf+asz, mvdata, vaddr+asz);
    }
    return asz;
}

void MVFn::add_pp(MVPP* pp) {
    pps.push_back(pp);
}

MVFn::MVFn(struct mv_info_fn& _fn, MVDataSection *mvdata, Section *mvtext, Section *rodata)
    :frozen{false} {
    fn = _fn;
    name = rodata->get_string(fn.name);

    if (fn.n_mv_functions == 0)
        return;

    auto mvfn_array = reinterpret_cast<const struct mv_info_mvfn*>
        (mvdata->in_buf(fn.mv_functions));
    for_each(mvfn_array, mvfn_array+fn.n_mv_functions, [&](auto minfo)
            { mvfns.push_back(make_unique<MVmvfn>(minfo, mvdata, mvtext));} );
}

void MVFn::probe_var(MVVar* var) {
    for (auto& mvfn : mvfns)
        mvfn->check_var(var, this);
}

void MVFn::probe_sym(struct symbol &sym) {
    smatch m;
    regex pat { "^" + name + "(\\.multiverse\\.(.+))?$" };
    if (regex_search(sym.name, m, pat)) {
        if (m[2].matched) // probe mvfn with part after multiverse
            for (auto& mvfn : mvfns)
                mvfn->probe_sym(sym, m[2].str());
        else
           symbol = sym;
    }
}

void MVFn::print() {
    cout << (active == fn.function_body ? " -> " : "    ")
         << name << "@0x" << hex << fn.function_body << ":0x" << symbol.sym.st_size
         << "  -  mvfn[] @0x" << fn.mv_functions<< "\n";

    for (auto &mvfn : mvfns) {
        auto mact = active == mvfn->location();
        mvfn->print(mact);
    }
    
    cout << "\tpatchpoints:\n";
    for (auto& pp : pps)
        pp->print();
    cout << "\n";
}

//---------------------MVVar---------------------------------------------------
MVVar::MVVar(struct mv_info_var _var, Section* rodata, Section* data)
        :frozen{false}, var{_var} {
    _name = rodata->get_string(var.name);
    in_data = (data->inside(var.variable_location));

    if (in_data) {
        //ignores signed
        switch (var.variable_width) {
            case 1:
                _value = reinterpret_cast<const uint8_t*>(data->in_buf(var.variable_location))[0];
                break;
            case 2:
                _value = reinterpret_cast<const uint16_t*>(data->in_buf(var.variable_location))[0];
                break;
            case 4:
                _value = reinterpret_cast<const uint32_t*>(data->in_buf(var.variable_location))[0];
                break;
            case 8:
                _value = reinterpret_cast<const uint64_t*>(data->in_buf(var.variable_location))[0];
                break;
            default:
                throw std::runtime_error("Unexpected variable_width.\n");
        }
    } else {
        _value = 0;
        cout << "Warning: Variable " << _name << " is uninitialized.\n";
    }
}

void MVVar::print() {
    cout << "Var: " << _name << "@0x" << location() << "\n"
         << "\twidth=" << var.variable_width  << " flags=[ "
         << (var.flag_tracked ? "tracked " : "")
         << (var.flag_signed ? "signed " : "" )
         << (var.flag_bound ? "bound " : "") << "]\n";
    for (auto& fn : fns)
        fn->print();
}

size_t MVVar::make_info(bool fpic, byte* buf, Section* sec, uint64_t vaddr) {
    auto v = reinterpret_cast<struct mv_info_var*>(buf);
    v->name = var.name;
    v->variable_location = var.variable_location;
    v->info = var.info;
    v->functions_head = nullptr;

    if (fpic) {
        sec->add_rela(vaddr+offsetof(struct mv_info_var, name), var.name);
        sec->add_rela(vaddr+offsetof(struct mv_info_var, variable_location), var.variable_location);
    }
    return sizeof(struct mv_info_var);
}

void MVVar::link_fn(MVFn* fn) {
    fns.insert(fn);
}

void MVVar::set_value(int v, Section* data) {
    _value = v;
    if (in_data) {
        assert(var.variable_width == 4); 
        auto b = reinterpret_cast<int32_t*>(data->out_buf(var.variable_location));
        b[0] = v;
    }
}

uint64_t MVVar::location() {
    return var.variable_location;
}

void MVVar::apply(Section* text, Section* mvtext, bool guard) {
    frozen = true;
    for (auto& f : fns)
        f->apply(text, mvtext, guard);
}

//---------------------MVPP---------------------------------------------------
static int location_len(mv_info_patchpoint_type type) {
    if (type == PP_TYPE_X86_CALL_INDIRECT)
        return 6;
    else
        return 5;
}

MVPP::MVPP(MVFn* fn) : _fn{fn} {
    fptr = (fn->fn.n_mv_functions == 0);
    pp.type     = PP_TYPE_X86_JUMP;
    pp.location = fn->location();
    function_body = 0;
}

MVPP::MVPP(struct mv_info_callsite& cs, Section* text, Section* mvtext) {
    function_body = cs.function_body;
    decode_callsite(cs, (text->inside(cs.call_label) ? text : mvtext));
}

size_t MVPP::make_info(bool fpic, byte* buf, Section* sec, uint64_t vaddr) {
    auto cs = reinterpret_cast<mv_info_callsite*>(buf);
    cs->function_body = function_body;
    cs->call_label = pp.location;
    if (fpic) {
        sec->add_rela(vaddr+offsetof(struct mv_info_callsite, function_body), function_body);
        sec->add_rela(vaddr+offsetof(struct mv_info_callsite, call_label), pp.location);
    }
    return sizeof(mv_info_callsite);
}

void MVPP::set_fn(MVFn* fn) {
    _fn = fn;
}

void MVPP::print() {
    auto type = pp.type == PP_TYPE_INVALID ? "invalid" :
        pp.type == PP_TYPE_X86_CALL ? "call(x86)" :
        pp.type == PP_TYPE_X86_CALL_INDIRECT ? "indirect call(x86)" :
        pp.type == PP_TYPE_X86_JUMP ? "jump(x86)" : "nope";
    cout << "\t\t@0x" << hex << pp.location << " Type:" << type
         << (fptr ? " <- fptr" : "") << "\n";
}

uint64_t MVPP::decode_callsite(struct mv_info_callsite& cs, Section* text) {
    pp.location = cs.call_label;
    auto op = reinterpret_cast<const uint8_t*>(text->in_buf(cs.call_label));
    uint64_t callee = 0;
    if (op[0] == 0xe8) { // normal call
        callee = cs.call_label + *(int*)(op + 1) + 5;
        pp.type = PP_TYPE_X86_CALL;
    } else if (op[0] == 0xff && op[1] == 0x15) { // indirect call (function ptr)
        callee = (uint64_t)(cs.call_label + *(int*)(op + 2) + 6);
        pp.type = PP_TYPE_X86_CALL_INDIRECT;
    } else
        throw std::runtime_error("Invalid patchpoint\n");
    return callee;
}

void MVPP::patchpoint_apply(struct mv_info_mvfn *mvfn, Section* text, Section* mvtext) {
    auto txt = (text->inside(pp.location) ? text : mvtext );
    auto op = reinterpret_cast<unsigned char*>(txt->out_buf(pp.location));
    uint32_t offset;
    switch(pp.type) {
        case PP_TYPE_X86_JUMP:
            op[0] = 0xe9; // jmp
            offset = (uintptr_t)mvfn->function_body - ((uintptr_t) pp.location + 5);
            *((uint32_t *)&op[1]) = offset;
            break;
        case PP_TYPE_X86_CALL:
        case PP_TYPE_X86_CALL_INDIRECT:
            // Oh, look. It has a very simple body!
            if (mvfn->type == MVFN_TYPE_NOP) {
                if (pp.type == PP_TYPE_X86_CALL_INDIRECT) {
                    memcpy(op, "\x66\x0F\x1F\x44\x00\x00", 6); // 6 byte NOP
                } else {
                    memcpy(op, "\x0F\x1F\x44\x00\x00", 5);     // 5 byte NOP
                }
            } else if (mvfn->type == MVFN_TYPE_CONSTANT) {
                op[0] = 0xb8; // mov $..., eax
                *(uint32_t *)(op + 1) = mvfn->constant;
                if (pp.type == PP_TYPE_X86_CALL_INDIRECT)
                    op[5] = '\x90'; // insert trailing NOP
            } else if (mvfn->type == MVFN_TYPE_CLI ||
                       mvfn->type == MVFN_TYPE_STI) {
                if (mvfn->type == MVFN_TYPE_CLI) {
                    op[0] = '\xfa'; // CLI
                } else {
                    op[0] = '\xfb'; // STI
                }
                if (pp.type == PP_TYPE_X86_CALL_INDIRECT) {
                    memcpy(&op[1], "\x0F\x1F\x44\x00\x00", 5); // 5 byte NOP
                } else {
                    memcpy(&op[1], "\x0F\x1F\x40\x00", 4);     // 4 byte NOP
                }
            } else {
                offset = (uintptr_t)mvfn->function_body - ((uintptr_t) pp.location + 5);
                op[0] = 0xe8; // call
                *((uint32_t *)&op[1]) = offset;
                if (pp.type == PP_TYPE_X86_CALL_INDIRECT)
                    op[5] = '\x90'; // insert trailing NOP
            }
            break;
        default:
            throw std::runtime_error("Could not apply patchpoint.");
    } 
    auto d = elf_getdata(txt->scn_out, nullptr); // Implizit diry_buf ?
    elf_flagdata(d, ELF_C_SET, ELF_F_DIRTY);
}

void MVPP::patchpoint_size(void **from, void**to) {
    char* loc = (char*)(pp.location);
    *from = loc;
    *to = loc + location_len(pp.type);
}
