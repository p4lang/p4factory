/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <p4utils/p4utils_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

extern int cheap_trie_main(int argc, char *argv[]);
extern int cheap_trie_main(int argc, char *argv[]);
extern int tommyds_main(void);
extern int circular_buffer_main(int argc, char *argv[]);
extern int rr_scheduler_drop(int argc, char *argv[]);
extern int rr_scheduler_no_drop(int argc, char *argv[]);
extern int rr_scheduler_sched(int argc, char *argv[]);
extern int prio_scheduler_sched(int argc, char *argv[]);

int aim_main(int argc, char* argv[])
{
    printf("Calling cheap_trie_main\n");
    AIM_ASSERT(cheap_trie_main(argc, argv) == 0);
    printf("Calling cheap_trie_main\n");
    AIM_ASSERT(cheap_trie_main(argc, argv) == 0);
    printf("Calling circular_buffer_main\n");
    AIM_ASSERT(circular_buffer_main(argc, argv) == 0);
    printf("Calling rr_scheduler_drop\n");
    AIM_ASSERT(rr_scheduler_drop(argc, argv) == 0);
    printf("Calling rr_scheduler_no_drop\n");
    AIM_ASSERT(rr_scheduler_no_drop(argc, argv) == 0);
    printf("Calling rr_scheduler_sched\n");
    AIM_ASSERT(rr_scheduler_sched(argc, argv) == 0);
    printf("Calling prio_scheduler_sched\n");
    AIM_ASSERT(prio_scheduler_sched(argc, argv) == 0);
    printf("Calling tommyds_main\n");
    AIM_ASSERT(tommyds_main() == 0);


    p4utils_config_show(&aim_pvs_stdout);
    return 0;
}

