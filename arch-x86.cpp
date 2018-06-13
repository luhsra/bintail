#include "string.h"
#include "bintail.h"

void multiverse_arch_decode_function(MVFn* fn, struct mv_patchpoint *pp) {
    pp->type     = PP_TYPE_X86_JUMP;
    pp->function = fn;
    pp->location = fn->location();
}

void multiverse_arch_decode_callsite(MVFn* fn, struct mv_info_callsite& cs,
        struct mv_patchpoint *info, Section* text) {
    auto *p = text->get_func_loc(cs.call_label);
    uint64_t callee = 0;

    if (p[0] == 0xe8) { // normal call
        callee = cs.call_label + *(int*)(p + 1) + 5;
        info->type = PP_TYPE_X86_CALL;
    } else if (p[0] == 0xff && p[1] == 0x15) { // indirect call (function ptr)
        callee = (uint64_t)(cs.call_label + *(int*)(p + 2) + 6);
        info->type = PP_TYPE_X86_CALL_INDIRECT;
    } else
        info->type = PP_TYPE_INVALID;

    info->function = fn; // ToDo(Felix): Is this used?
    info->location = cs.call_label;
    fn->active = callee;
}

static int is_ret(uint8_t* addr) {
    //    c3: retq
    // f3 c3: repz retq
    return (memcmp(addr, "\xc3", 1) == 0)
        || (memcmp(addr, "\xf3\xc3", 2) == 0);
}

static int location_len(mv_info_patchpoint_type type) {
    if (type == PP_TYPE_X86_CALL_INDIRECT) {
        return 6;
    } else {
        return 5;
    }
}

void multiverse_arch_decode_mvfn_body(struct mv_info_mvfn *info, uint8_t * op) {
    // 31 c0: xor    %eax,%eax
    //    c3: retq
    if (memcmp(op, "\x31\xc0", 2) == 0 && is_ret(op + 2)) {
        // multiverse_os_print("eax = 0\n");
        info->type = MVFN_TYPE_CONSTANT;
        info->constant = 0;
    } else if (memcmp(op, "\xb8", 1) == 0 && is_ret(op + 5)) {
        info->type = MVFN_TYPE_CONSTANT;
        info->constant = *(uint32_t *)(op +1);
        // multiverse_os_print("eax = %d\n", info->constant);
    } else if (is_ret(op)) {
        // multiverse_os_print("NOP\n");
        info->type = MVFN_TYPE_NOP;
    } else if (memcmp(op, "\xfa", 1) == 0 && is_ret(op + 1)) {
        info->type = MVFN_TYPE_CLI;
    } else if (memcmp(op, "\xfb", 1) == 0 && is_ret(op + 1)) {
        info->type = MVFN_TYPE_STI;
    } else {
        info->type = MVFN_TYPE_NONE;
    }
}

static void insert_offset_argument(uint8_t* callsite, void * callee) {
    uint32_t offset = (uintptr_t)callee - ((uintptr_t) callsite + 5);
    *((uint32_t *)&callsite[1]) = offset;
}

void multiverse_arch_patchpoint_apply(struct mv_info_mvfn *mvfn,
        struct mv_patchpoint *pp, Section* text) {
    auto location = text->get_func_loc(pp->location);
    auto dest = text->get_func_loc(mvfn->function_body);

    switch(pp->type) {
        case PP_TYPE_X86_JUMP:
            location[0] = 0xe9;
            insert_offset_argument(location, dest);
            break;
        case PP_TYPE_X86_CALL:
        case PP_TYPE_X86_CALL_INDIRECT:
            // Oh, look. It has a very simple body!
            if (mvfn->type == MVFN_TYPE_NOP) {
                if (pp->type == PP_TYPE_X86_CALL_INDIRECT) {
                    memcpy(location, "\x66\x0F\x1F\x44\x00\x00", 6); // 6 byte NOP
                } else {
                    memcpy(location, "\x0F\x1F\x44\x00\x00", 5);     // 5 byte NOP
                }
            } else if (mvfn->type == MVFN_TYPE_CONSTANT) {
                location[0] = 0xb8; // mov $..., eax
                *(uint32_t *)(location + 1) = mvfn->constant;
                if (pp->type == PP_TYPE_X86_CALL_INDIRECT)
                    location[5] = '\x90'; // insert trailing NOP
            } else if (mvfn->type == MVFN_TYPE_CLI ||
                       mvfn->type == MVFN_TYPE_STI) {
                if (mvfn->type == MVFN_TYPE_CLI) {
                    location[0] = '\xfa'; // CLI
                } else {
                    location[0] = '\xfb'; // STI
                }
                if (pp->type == PP_TYPE_X86_CALL_INDIRECT) {
                    memcpy(&location[1], "\x0F\x1F\x44\x00\x00", 5); // 5 byte NOP
                } else {
                    memcpy(&location[1], "\x0F\x1F\x40\x00", 4);     // 4 byte NOP
                }
            } else {
                location[0] = 0xe8;
                insert_offset_argument(location, dest);
                if (pp->type == PP_TYPE_X86_CALL_INDIRECT)
                    location[5] = '\x90'; // insert trailing NOP
            }
            break;
        default:
            cerr << "Could not apply patchpoint: " 
                << hex << pp->location << endl;
            return;
    } 
    text->set_dirty();
}

void multiverse_arch_patchpoint_revert(struct mv_patchpoint *pp) {
    auto location = (char*)(pp->location);
    int size = location_len(pp->type);
    // Revert to original state
    memcpy((void*)pp->location, &pp->swapspace[0], size);
    __builtin___clear_cache((char*)location, location+size);
}

void multiverse_arch_patchpoint_size(struct mv_patchpoint *pp,
                                     void **from,
                                     void**to) {
    char* loc = (char*)(pp->location);
    *from = loc;
    *to = loc + location_len(pp->type);
}
