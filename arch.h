/**
  @file The hardware architecture specific stubs

  The architecture functionality includes the decoding of callsites,
  mvfn function bodies and the actual callsite/function patching.
*/
#ifndef __MULTIVERSE_ARCH_H
#define __MULTIVERSE_ARCH_H

#include <memory>
using namespace std;

class Section;
class MVFn;
#ifdef __cplusplus
extern "C" {
#endif

struct mv_info_mvfn;
struct mv_info_mvfn_extra;

/**
   @brief Decode callee site into the patchpoint

   This architecture specfic function decodes the callee at addr and
   fills in the patchpoint information. On success the patchpoint type
   is != PP_TYPE_INVALID.
*/
void multiverse_arch_decode_function(MVFn* fn, struct mv_patchpoint *pp);

/**
  @brief Decode callsite and fill patchpoint info

  This architecture specfic function decodes the callsite at addr and
  fills in the patchpoint information. On success the patchpoint type
  is != PP_TYPE_INVALID.
*/
void multiverse_arch_decode_callsite(MVFn* fn, struct mv_info_callsite& cs,
                                      struct mv_patchpoint *pp, Section* text);

/**
  @brief decode mvfn function body

  If a multiverse function body does nothing, or only returns a
  constant value, we can further optimize the patched callsites. For a
  dummy architecture implementation, this operation can be implemented
  as a NOP.
*/

void multiverse_arch_decode_mvfn_body(struct mv_info_mvfn *info, uint8_t * op);

/**
  @brief applies the mvfn to the patchpoint
*/
void multiverse_arch_patchpoint_apply(struct mv_info_mvfn *mvfn,
                                      struct mv_patchpoint *pp, Section* text);

/**
   @brief restores the code to the original form
*/
void multiverse_arch_patchpoint_revert(struct mv_patchpoint *pp);

/**
 * @brief Translates a patchpoint into two pointers indicating the
 * begin and the end of the patchpoint. In the OS layer, these points
 * are translated to page pointers.
 */
void multiverse_arch_patchpoint_size(struct mv_patchpoint *pp,
                                     void **from, void** to);
#ifdef __cplusplus
} // extern "C"
#endif

#endif
