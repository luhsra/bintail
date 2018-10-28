/*
 * Executable with multiverse attributes, but without libmultiverse
 */

#include <stdio.h>
#ifdef MVINSTALLED
#include <multiverse/multiverse.h>
#else
#include "multiverse.h"
#endif

__attribute__((multiverse)) int config;

void __attribute__((multiverse)) func() {
    if (config)
        puts("true");
    else
        puts("false");
}

int main()
{
    multiverse_init();
    func();

    return 0;
}
