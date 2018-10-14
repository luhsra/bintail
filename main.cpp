#include <iostream>
#include <string>
#include <vector>
#include <getopt.h>

using namespace std;

#include "bintail.h"

int main(int argc, char *argv[]) {
    auto apply_all = false;
    auto display = false;
    auto write = true;
    auto guard = false;
    auto dyn = false;
    auto sym = false;
    auto mvreloc = false;
    vector<string> changes;
    vector<string> apply;
    
    int opt;
    int rt = 1;
    while ((opt = getopt(argc, argv, "a:Adhglrs:twy")) != -1) {
        switch (opt) {
        case 'a':
            apply.push_back(optarg);
            break;
        case 'A':
            apply_all = true;
            break;
        case 'd':
            display = true;
            break;
        case 'g':
            guard = true;
            break;
        case 'l':
            dyn = true;
            break;
        case 'r':
            mvreloc = true;
            break;
        case 's':
            changes.push_back(optarg);
            break;
        case 'y':
            sym = true;
            break;
        case 'h':
            rt = 0;
        default:
            cerr << "Usage: bintail [-d] [-w] infile outfile\n"
                 << "Tailor multiverse executable\n"
                 << "\n"
                 << "-a var         Apply variable.\n"
                 << "-A             Apply all variables.\n"
                 << "-d             Display multiverse configuration.\n"
                 << "-h             Print help.\n"
                 << "-l             Show dynamic info.\n"
                 << "-r             Dump mvrelocs.\n"
                 << "-s var=value   Set variable to value.\n"
                 << "-y             Dump Symbols.\n"
                 << "\n";
            return rt;
        }
    }
    if (optind+2 != argc) {
        if (optind+1 == argc) {
            write = false;
        } else {
            cerr << "Expected 1-2 arguments\n";
            return 1;
        }
    }

    auto infile = argv[optind];
    auto outfile = argv[optind+1];
    Bintail bintail{infile};

    if (sym)
        bintail.print_sym();
    if (dyn)
        bintail.print_dyn();
    if (mvreloc)
        bintail.print_reloc();
    if (display)
        bintail.print();

    if (!write)
        return 0;

    bintail.init_write(outfile);

    for (auto& e : changes)
        bintail.change(e);
    for (auto& e : apply)
        bintail.apply(e, guard);
    if (apply_all)
        bintail.apply_all(guard);

    bintail.write();

    return 0;
}
