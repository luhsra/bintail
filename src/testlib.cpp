#include <bintail/bintail.h>

int main(int argc, char *argv[]) {
    if (argc>2)
        abort();
    auto infile = argv[1];
    auto outfile = argv[2];
    Bintail bintail{infile};
    bintail.init_write(outfile, true);
    bintail.apply_all(true);
    //bintail.write();

    return 0;
}
