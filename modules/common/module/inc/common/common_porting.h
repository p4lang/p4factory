/**************************************************************************//**
 *
 * @file
 * @brief common Porting Macros.
 *
 * @addtogroup common-porting
 * @{
 *
 *****************************************************************************/
#ifndef __COMMON_PORTING_H__
#define __COMMON_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef COMMON_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define COMMON_MALLOC GLOBAL_MALLOC
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_MALLOC malloc
    #else
        #error The macro COMMON_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef COMMON_FREE
    #if defined(GLOBAL_FREE)
        #define COMMON_FREE GLOBAL_FREE
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_FREE free
    #else
        #error The macro COMMON_FREE is required but cannot be defined.
    #endif
#endif

#ifndef COMMON_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define COMMON_MEMSET GLOBAL_MEMSET
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_MEMSET memset
    #else
        #error The macro COMMON_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef COMMON_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define COMMON_MEMCPY GLOBAL_MEMCPY
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_MEMCPY memcpy
    #else
        #error The macro COMMON_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef COMMON_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define COMMON_STRNCPY GLOBAL_STRNCPY
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_STRNCPY strncpy
    #else
        #error The macro COMMON_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef COMMON_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define COMMON_VSNPRINTF GLOBAL_VSNPRINTF
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_VSNPRINTF vsnprintf
    #else
        #error The macro COMMON_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef COMMON_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define COMMON_SNPRINTF GLOBAL_SNPRINTF
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_SNPRINTF snprintf
    #else
        #error The macro COMMON_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef COMMON_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define COMMON_STRLEN GLOBAL_STRLEN
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_STRLEN strlen
    #else
        #error The macro COMMON_STRLEN is required but cannot be defined.
    #endif
#endif

#ifndef COMMON_STRNCMP
    #if defined(GLOBAL_STRNCMP)
        #define COMMON_STRNCMP GLOBAL_STRNCMP
    #elif COMMON_CONFIG_PORTING_STDLIB == 1
        #define COMMON_STRNCMP strncmp
    #else
        #error The macro COMMON_STRNCMP is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __COMMON_PORTING_H__ */
/* @} */
