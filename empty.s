.text
.globl start
start:
        movq $0xffff, %rax
        syscall
