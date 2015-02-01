all: linux-process emu

LLVM = $(shell llvm-config --cflags --ldflags --system-libs --libs mcdisassembler x86)
CFLAGS = -g3 -lc++ $(LLVM) -Iinclude -Wall -Werror -Wno-unused-function

emu: emu.c uthash.h
	clang -O0 $(CFLAGS) $(filter %.c,$^) -o $@

linux-process.o: linux-process.s
	as $< -o $@

linux-process: linux-process.o
	ld $< -o $@ -no_pie -static -macosx_version_min 10.5 -pagezero_size 0x1000 -no_uuid

clean:
	rm -rf *.o *.dSYM emu linux-process
