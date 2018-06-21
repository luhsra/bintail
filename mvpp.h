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
    MVFn* function;
    uint64_t location;                // == callsite call_label
    mv_info_patchpoint_type type;

    // Here we swap in the code, we overwrite
    unsigned char swapspace[6];
};

class MVPP {
public:
    MVPP(MVFn* fn);
    MVPP(struct mv_info_callsite& cs, MVFn* fn, Section* text);
    bool invalid();
    void print(Section* text);

    /**
       @brief Decode callee site into the patchpoint

       This architecture specfic function decodes the callee at addr and
       fills in the patchpoint information. On success the patchpoint type
       is != PP_TYPE_INVALID.
    */
    void decode_function(MVFn* fn);

    /**
      @brief Decode callsite and fill patchpoint info

      This architecture specfic function decodes the callsite at addr and
      fills in the patchpoint information. On success the patchpoint type
      is != PP_TYPE_INVALID.
    */
    void decode_callsite(MVFn* fn, struct mv_info_callsite& cs, Section* text);

    /**
      @brief applies the mvfn to the patchpoint
    */
    void patchpoint_apply(struct mv_info_mvfn *mvfn, Section* text);

    /**
       @brief restores the code to the original form
    */
    void patchpoint_revert();

    /**
     * @brief Translates a patchpoint into two pointers indicating the
     * begin and the end of the patchpoint. In the OS layer, these points
     * are translated to page pointers.
     */
    void patchpoint_size(void **from, void** to);

    struct mv_patchpoint pp;
private:
    bool fptr;
};


#endif
