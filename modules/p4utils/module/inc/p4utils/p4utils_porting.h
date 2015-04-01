/**************************************************************************//**
 *
 * @file
 * @brief p4utils Porting Macros.
 *
 * @addtogroup p4utils-porting
 * @{
 *
 *****************************************************************************/
#ifndef __P4UTILS_PORTING_H__
#define __P4UTILS_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if P4UTILS_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef P4UTILS_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define P4UTILS_MALLOC GLOBAL_MALLOC
    #elif P4UTILS_CONFIG_PORTING_STDLIB == 1
        #define P4UTILS_MALLOC malloc
    #else
        #error The macro P4UTILS_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef P4UTILS_FREE
    #if defined(GLOBAL_FREE)
        #define P4UTILS_FREE GLOBAL_FREE
    #elif P4UTILS_CONFIG_PORTING_STDLIB == 1
        #define P4UTILS_FREE free
    #else
        #error The macro P4UTILS_FREE is required but cannot be defined.
    #endif
#endif

#ifndef P4UTILS_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define P4UTILS_MEMSET GLOBAL_MEMSET
    #elif P4UTILS_CONFIG_PORTING_STDLIB == 1
        #define P4UTILS_MEMSET memset
    #else
        #error The macro P4UTILS_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef P4UTILS_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define P4UTILS_MEMCPY GLOBAL_MEMCPY
    #elif P4UTILS_CONFIG_PORTING_STDLIB == 1
        #define P4UTILS_MEMCPY memcpy
    #else
        #error The macro P4UTILS_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef P4UTILS_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define P4UTILS_STRNCPY GLOBAL_STRNCPY
    #elif P4UTILS_CONFIG_PORTING_STDLIB == 1
        #define P4UTILS_STRNCPY strncpy
    #else
        #error The macro P4UTILS_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef P4UTILS_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define P4UTILS_VSNPRINTF GLOBAL_VSNPRINTF
    #elif P4UTILS_CONFIG_PORTING_STDLIB == 1
        #define P4UTILS_VSNPRINTF vsnprintf
    #else
        #error The macro P4UTILS_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef P4UTILS_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define P4UTILS_SNPRINTF GLOBAL_SNPRINTF
    #elif P4UTILS_CONFIG_PORTING_STDLIB == 1
        #define P4UTILS_SNPRINTF snprintf
    #else
        #error The macro P4UTILS_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef P4UTILS_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define P4UTILS_STRLEN GLOBAL_STRLEN
    #elif P4UTILS_CONFIG_PORTING_STDLIB == 1
        #define P4UTILS_STRLEN strlen
    #else
        #error The macro P4UTILS_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __P4UTILS_PORTING_H__ */
/* @} */
