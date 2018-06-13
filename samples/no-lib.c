/*
 * Executable with multiverse attributes, but without libmultiverse
 */

#include <stdio.h>
#include <multiverse/multiverse.h>

typedef enum {false, true} bool;

__attribute__((multiverse, section(".data"))) bool config_first = false;
__attribute__((multiverse, section(".data"))) bool config_second = true;
__attribute__((multiverse, section(".data"))) bool config_third = false;

void __attribute__((multiverse)) func_first()
{
    if (config_first)
        puts("config_first = true");
    else
        puts("config_first = false");
}

void __attribute__((multiverse)) func_second()
{
    if (config_second)
        puts("config_second = true");
    else
        puts("config_second = false");
}

void __attribute__((multiverse)) func_third()
{
    if (config_third)
        puts("config_third = true");
    else
        puts("config_third = false");
}

int main()
{
    multiverse_init();

    func_first();
    func_second();
    func_third();

    multiverse_dump_info();

    return 0;
}
