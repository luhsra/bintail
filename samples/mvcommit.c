/*
 * Executable with multiverse attributes, but without libmultiverse
 */

#include <stdio.h>
#ifdef MVINSTALLED
#include <multiverse.h>
#else
#include "multiverse.h"
#endif

__attribute__((multiverse, section(".data"))) int config_first = 0;

void __attribute__((multiverse)) func() {
    if (config_first)
        puts("config_first = true");
    else
        puts("config_first = false");
}

int main()
{
    multiverse_init();

    func();
    multiverse_dump_info();

    multiverse_commit_refs(&config_first);
    func();
    multiverse_dump_info();

    return 0;
}
