/**************************************************************************//**
 *
 * @file
 * @brief common Configuration Header
 *
 * @addtogroup common-config
 * @{
 *
 *****************************************************************************/
#ifndef __COMMON_CONFIG_H__
#define __COMMON_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef COMMON_INCLUDE_CUSTOM_CONFIG
#include <common_custom_config.h>
#endif

/* <auto.start.cdefs(COMMON_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * COMMON_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef COMMON_CONFIG_INCLUDE_LOGGING
#define COMMON_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * COMMON_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef COMMON_CONFIG_LOG_OPTIONS_DEFAULT
#define COMMON_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * COMMON_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef COMMON_CONFIG_LOG_BITS_DEFAULT
#define COMMON_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * COMMON_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef COMMON_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define COMMON_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * COMMON_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef COMMON_CONFIG_PORTING_STDLIB
#define COMMON_CONFIG_PORTING_STDLIB 1
#endif

/**
 * COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS COMMON_CONFIG_PORTING_STDLIB
#endif

/**
 * COMMON_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef COMMON_CONFIG_INCLUDE_UCLI
#define COMMON_CONFIG_INCLUDE_UCLI 0
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct common_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} common_config_settings_t;

/** Configuration settings table. */
/** common_config_settings table. */
extern common_config_settings_t common_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* common_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int common_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(COMMON_CONFIG_HEADER).header> */

#include <common/common_porting.h>

#endif /* __COMMON_CONFIG_H__ */
/* @} */
