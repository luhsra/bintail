#include <iostream>
#include <cassert>

using namespace std;

#include "string.h"
#include "bintail.h"
#include "mvpp.h"

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

void MVPP::make_info(mv_info_callsite* cs, Section* sec, uint64_t off) {
    GElf_Rela r1, r2;
    
    cs->function_body = function_body;
    r1.r_addend = cs->function_body;
    r1.r_info = R_X86_64_RELATIVE;
    r1.r_offset = off;
    sec->relocs.push_back(r1);

    cs->call_label = pp.location;
    r2.r_addend = cs->call_label;
    r2.r_info = R_X86_64_RELATIVE;
    r2.r_offset = off+sizeof(uint64_t);
    sec->relocs.push_back(r2);
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
        cout << "\t\t@.text:0x" << hex << pp.location - txt->vaddr() << " Type:" << type;
    } else {
        txt = mvtext;
        cout << "\t\t@.mvtext:0x" << hex << pp.location - txt->vaddr() << " Type:" << type;
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
    text->set_dirty();
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
