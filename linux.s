.text
.globl start
start:
        movq $0x1122334455667788, %rax
        movq $0x99AABBCCDDEEFF00, %r15
        syscall

        movq $1, %rax
        movq $1, %rdi
        leaq msg(%rip), %rsi
        movq $(msgend - msg), %rdx
        syscall

        movq $60, %rax
        movq $0, %rdi
        syscall

.data
msg:    .asciz "Hello, world\n"
msgend:
