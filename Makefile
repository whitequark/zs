all: linux emulinux

emulinux: emulinux.c
	clang -g2 $^ -o $@

linux: linux.s
	clang -c $^
	ld $(patsubst %.s,%.o,$^) -o $@

clean:
	rm -f *.o emulinux emulinux.dSYM linux
