/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <common/common_config.h>

/* <auto.start.cdefs(COMMON_CONFIG_HEADER).source> */
#define __common_config_STRINGIFY_NAME(_x) #_x
#define __common_config_STRINGIFY_VALUE(_x) __common_config_STRINGIFY_NAME(_x)
common_config_settings_t common_config_settings[] =
{
#ifdef COMMON_CONFIG_INCLUDE_LOGGING
    { __common_config_STRINGIFY_NAME(COMMON_CONFIG_INCLUDE_LOGGING), __common_config_STRINGIFY_VALUE(COMMON_CONFIG_INCLUDE_LOGGING) },
#else
{ COMMON_CONFIG_INCLUDE_LOGGING(__common_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef COMMON_CONFIG_LOG_OPTIONS_DEFAULT
    { __common_config_STRINGIFY_NAME(COMMON_CONFIG_LOG_OPTIONS_DEFAULT), __common_config_STRINGIFY_VALUE(COMMON_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ COMMON_CONFIG_LOG_OPTIONS_DEFAULT(__common_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef COMMON_CONFIG_LOG_BITS_DEFAULT
    { __common_config_STRINGIFY_NAME(COMMON_CONFIG_LOG_BITS_DEFAULT), __common_config_STRINGIFY_VALUE(COMMON_CONFIG_LOG_BITS_DEFAULT) },
#else
{ COMMON_CONFIG_LOG_BITS_DEFAULT(__common_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef COMMON_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __common_config_STRINGIFY_NAME(COMMON_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __common_config_STRINGIFY_VALUE(COMMON_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ COMMON_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__common_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef COMMON_CONFIG_PORTING_STDLIB
    { __common_config_STRINGIFY_NAME(COMMON_CONFIG_PORTING_STDLIB), __common_config_STRINGIFY_VALUE(COMMON_CONFIG_PORTING_STDLIB) },
#else
{ COMMON_CONFIG_PORTING_STDLIB(__common_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __common_config_STRINGIFY_NAME(COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __common_config_STRINGIFY_VALUE(COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ COMMON_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__common_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef COMMON_CONFIG_INCLUDE_UCLI
    { __common_config_STRINGIFY_NAME(COMMON_CONFIG_INCLUDE_UCLI), __common_config_STRINGIFY_VALUE(COMMON_CONFIG_INCLUDE_UCLI) },
#else
{ COMMON_CONFIG_INCLUDE_UCLI(__common_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __common_config_STRINGIFY_VALUE
#undef __common_config_STRINGIFY_NAME

const char*
common_config_lookup(const char* setting)
{
    int i;
    for(i = 0; common_config_settings[i].name; i++) {
        if(strcmp(common_config_settings[i].name, setting)) {
            return common_config_settings[i].value;
        }
    }
    return NULL;
}

int
common_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; common_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", common_config_settings[i].name, common_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(COMMON_CONFIG_HEADER).source> */

