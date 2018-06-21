#include <iostream>
#include <string>
#include <vector>
#include <getopt.h>

#include "bintail.h"

void help() {
    std::cout << "USAGE: bintail [-d] [-w] -f <filename>\n"
              << "Tailor multiverse executable\n"
              << "\n"
              << "-a var         Apply variable.\n"
              << "-d             Display multiverse configuration.\n"
              << "-f             File to edit.\n"
              << "-h             Print help.\n"
              << "-s var=value   Set variable to value.\n"
              << "-t             Trim fixed multiverse data.\n"
              << "-w             Write file.\n"
              << "-y             Dump Symbols.\n"
              << "\n";
}

int main(int argc, char *argv[]) {
    auto filename = "./"s;
    auto display = false;
    auto write = false;
    auto trim = false;
    auto sym = false;
    vector<string> changes;
    vector<string> apply;
    
    int opt;
    while ((opt = getopt(argc, argv, "a:df:hs:twy")) != -1) {
        switch (opt) {
        case 'a':
            apply.push_back(optarg);
            break;
        case 'd':
            display = true;
            break;
        case 'f':
            filename += optarg;
            break;
        case 'h':
            help();
            break;
        case 's':
            changes.push_back(optarg);
            break;
        case 't':
            trim = true;
            break;
        case 'w':
            write = true;
            break;
        case 'y':
            sym = true;
            break;
        default:
            cerr << "Wrong args.\n";
            help();
            return 1;
        }
    }

    Bintail bintail{filename};
    bintail.load();

    for (auto& e : changes)
        bintail.change(e);

    for (auto& e : apply)
        bintail.apply(e);
    
    if (display)
        bintail.print();
    if (sym)
        bintail.print_sym();
    if (trim)
        bintail.trim();
    if (write)
        bintail.write();

    return 0;
}

