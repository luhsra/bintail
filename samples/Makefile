CC = gcc

CFLAGS  = -ggdb -fplugin=multiverse -O2 -Wextra
LDLIBS  = -lmultiverse

SOURCES=$(shell echo *.c)
SAMPLES=$(foreach x,${SOURCES},$(patsubst %.c,%,$x))

all: $(SAMPLES)
