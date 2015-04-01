/**************************************************************************//**
 *
 * @file
 * @brief p4ns_common Porting Macros.
 *
 * @addtogroup p4ns_common-porting
 * @{
 *
 *****************************************************************************/
#ifndef __P4NS_COMMON_PORTING_H__
#define __P4NS_COMMON_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if P4NS_COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef P4NS_COMMON_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define P4NS_COMMON_MALLOC GLOBAL_MALLOC
    #elif P4NS_COMMON_CONFIG_PORTING_STDLIB == 1
        #define P4NS_COMMON_MALLOC malloc
    #else
        #error The macro P4NS_COMMON_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef P4NS_COMMON_FREE
    #if defined(GLOBAL_FREE)
        #define P4NS_COMMON_FREE GLOBAL_FREE
    #elif P4NS_COMMON_CONFIG_PORTING_STDLIB == 1
        #define P4NS_COMMON_FREE free
    #else
        #error The macro P4NS_COMMON_FREE is required but cannot be defined.
    #endif
#endif

#ifndef P4NS_COMMON_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define P4NS_COMMON_MEMSET GLOBAL_MEMSET
    #elif P4NS_COMMON_CONFIG_PORTING_STDLIB == 1
        #define P4NS_COMMON_MEMSET memset
    #else
        #error The macro P4NS_COMMON_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef P4NS_COMMON_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define P4NS_COMMON_MEMCPY GLOBAL_MEMCPY
    #elif P4NS_COMMON_CONFIG_PORTING_STDLIB == 1
        #define P4NS_COMMON_MEMCPY memcpy
    #else
        #error The macro P4NS_COMMON_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef P4NS_COMMON_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define P4NS_COMMON_STRNCPY GLOBAL_STRNCPY
    #elif P4NS_COMMON_CONFIG_PORTING_STDLIB == 1
        #define P4NS_COMMON_STRNCPY strncpy
    #else
        #error The macro P4NS_COMMON_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef P4NS_COMMON_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define P4NS_COMMON_VSNPRINTF GLOBAL_VSNPRINTF
    #elif P4NS_COMMON_CONFIG_PORTING_STDLIB == 1
        #define P4NS_COMMON_VSNPRINTF vsnprintf
    #else
        #error The macro P4NS_COMMON_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef P4NS_COMMON_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define P4NS_COMMON_SNPRINTF GLOBAL_SNPRINTF
    #elif P4NS_COMMON_CONFIG_PORTING_STDLIB == 1
        #define P4NS_COMMON_SNPRINTF snprintf
    #else
        #error The macro P4NS_COMMON_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef P4NS_COMMON_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define P4NS_COMMON_STRLEN GLOBAL_STRLEN
    #elif P4NS_COMMON_CONFIG_PORTING_STDLIB == 1
        #define P4NS_COMMON_STRLEN strlen
    #else
        #error The macro P4NS_COMMON_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __P4NS_COMMON_PORTING_H__ */
/* @} */
