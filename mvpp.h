#ifndef __MVPP_H
#define __MVPP_H

#include <memory>

#include "bintail.h"
#include "mvvar.h"

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

    // Here we swap in the code, we overwrite
    unsigned char swapspace[6];
};

class MVPP {
public:
    MVPP(MVFn* fn);
    MVPP(struct mv_info_callsite& cs, Section* text, Section* mvtext);
    bool invalid();
    void print(Section* text, Section* mvtext);
    void set_fn(MVFn* fn);
    void make_info(mv_info_callsite* cs, Section* sec, uint64_t off);

    /* ret callee */
    uint64_t decode_callsite(struct mv_info_callsite& cs, Section* text);

    void patchpoint_apply(struct mv_info_mvfn *mvfn, Section* text, Section* mvtext);
    void patchpoint_revert();
    void patchpoint_size(void **from, void** to);

    struct mv_patchpoint pp;
    uint64_t function_body;
    MVFn* _fn;
private:
    bool fptr;
};


#endif
