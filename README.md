# Bintail
__Bintail__ is a static variability application tool for multiverse executables.

## Dependencies

* Function multiverse
* x86-64 ELF executable
* Linux

## Build

```bash
$ git clone https://github.com/luhsra/bintail.git && cd ./bintail
$ mkdir build && cd build
$ cmake ..
$ make
```

## Usage

```bash
$ bintail -d exe_in
$ bintail -a config exe_in exe_out
$ bintail -s config=0 exe_in exe_out
```
