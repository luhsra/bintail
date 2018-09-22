CC = gcc

ifneq (${SESSION},ubuntu)
	MV_DIR=../../multiverse
	PLUGIN_DIR=$(MV_DIR)/gcc-plugin
	PLUGIN=$(PLUGIN_DIR)/multiverse.so
	LIBRARY_DIR=$(MV_DIR)/libmultiverse
	LIBRARY=$(LIBRARY_DIR)/libmultiverse.a
	
	CFLAGS  = -g -fpie -fpic -fplugin=$(PLUGIN) -I$(LIBRARY_DIR) -O2 -Wextra
	LDFLAGS = -L$(LIBRARY_DIR) #-Wl,--emit-relocs
else
	CFLAGS  = -g -fplugin=multiverse -DMVINSTALLED -O0 -Wextra
endif
LDLIBS  = -lmultiverse

SOURCES=$(shell echo *.c)
SAMPLES=$(foreach x,${SOURCES},$(patsubst %.c,%,$x))

all: $(SAMPLES)

clean:
	rm -f $(SAMPLES)
