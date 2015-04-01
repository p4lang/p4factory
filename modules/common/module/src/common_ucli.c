/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <common/common_config.h>

#if COMMON_CONFIG_INCLUDE_UCLI == 1

#include <uCli/ucli.h>
#include <uCli/ucli_argparse.h>
#include <uCli/ucli_handler_macros.h>


static ucli_status_t
common_ucli_ucli__echo__(ucli_context_t* uc)
{
    int i;

    UCLI_COMMAND_INFO(uc,
                      "echo", 1,
                      "Echo command data.");

    for(i = 0; i < uc->pargs->count; i++) {
        aim_printf(&uc->pvs, "%s\n", uc->pargs->args[i]);
    }

    return UCLI_STATUS_OK;
}

static ucli_status_t
common_ucli_ucli__config__(ucli_context_t* uc)
{
    UCLI_HANDLER_MACRO_MODULE_CONFIG(common)
}

/* <auto.ucli.handlers.start> */
static ucli_command_handler_f common_ucli_ucli_handlers__[] =
{
    common_ucli_ucli__config__,
    common_ucli_ucli__echo__,
    NULL
};
/* <auto.ucli.handlers.end> */

static ucli_module_t
common_ucli_module__ =
    {
        "common_ucli",
        NULL,
        common_ucli_ucli_handlers__,
        NULL,
        NULL,
    };

ucli_node_t*
common_ucli_node_create(void)
{
    ucli_node_t* n;
    ucli_module_init(&common_ucli_module__);
    n = ucli_node_create("common", NULL, &common_ucli_module__);
    ucli_node_subnode_add(n, ucli_module_log_node_create("common"));
    return n;
}

#else
void*
common_ucli_node_create(void)
{
    return NULL;
}
#endif

