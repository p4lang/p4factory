/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <common/common_config.h>

#include <common/portmanager.h>

#include <SocketManager/socketmanager.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

#define TEST_IFACE        "udp|send:127.0.0.1:30001"
#define TEST_OF_PORT_NUM  1

static void
assert_report(unsigned line, char *expr)
{
    printf("FAILED: line=%u, expr=\"%s\"\n", line, expr);
}

#define CHECK(expr) \
    do { if (!(expr)) { assert_report(__LINE__, # expr); } } while (0)

extern int common_c_gtest_main(int argc, char **argv);
extern int common_c_f(int x, int *y);

int aim_main(int argc, char* argv[])
{
    fprintf(stderr, "Config dump\n");
    common_config_show(&aim_pvs_stdout);

    /* Test calls to socket and port managers */
    {
        /* Init socket manager */
        CHECK(ind_soc_init(NULL) == 0);
        /* Add a port */
        CHECK(p4_port_init(10) == P4_E_NONE);
        CHECK(p4_port_interface_add(TEST_IFACE, TEST_OF_PORT_NUM) ==
              P4_E_NONE);
        ind_soc_enable_set(1);

        CHECK(p4_port_interface_remove(TEST_IFACE) == P4_E_NONE);
        ind_soc_finish();
    }

    return 0;
}

