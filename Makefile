all: app emu

LLVM = $(shell llvm-config --cflags --ldflags --system-libs --libs mcdisassembler x86)

emu: emu.c
	clang -g2 -lc++ $(LLVM) -Iinclude -Wall -Werror -Wno-unused-function $^ -o $@

app: app.s
	clang -c $^
	ld $(patsubst %.s,%.o,$^) -o $@

clean:
	rm -rf *.o emu emu.dSYM linux
