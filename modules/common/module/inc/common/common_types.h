/* @fixme top matter */

#ifndef _COMMON_TYPES_H_
#define _COMMON_TYPES_H_

#define COMPILER_REFERENCE(ref) (void) (ref)

typedef enum p4_error_s {
    P4_E_NONE=0,
    P4_E_PARAM=-1,
    P4_E_EXISTS=-2,
    P4_E_UNKNOWN=-3,
    P4_E_NOT_SUPPORTED=-4,
    P4_E_NOT_FOUND=-5
} p4_error_t;

#endif /* _COMMON_TYPES_H_ */
