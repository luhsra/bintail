/*
 * Executable with multiverse attributes, but without libmultiverse
 */

#include <stdio.h>
#include <multiverse/multiverse.h>

__attribute__((multiverse, section(".data"))) int config = 0;

void __attribute__((multiverse)) func() {
    if (config)
        puts("config_first = true");
    else
        puts("config_first = false");
}

int main()
{
    multiverse_init();

    func();
    multiverse_dump_info();

    multiverse_commit_refs(&config);
    func();
    multiverse_dump_info();

    return 0;
}
