all: app emu

emu: emu.c
	clang -g2 -Iinclude -Wall -Werror -Wno-unused-function $^ -o $@

app: app.s
	clang -c $^
	ld $(patsubst %.s,%.o,$^) -o $@

clean:
	rm -f *.o emu emu.dSYM linux
