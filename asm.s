.globl _start
_start:
//movq  $60, %rax
//movq  $0, %rdi
    leave
    ret
    syscall
    nop

    clc
    stc
    cli
    sti
    cld
    std
