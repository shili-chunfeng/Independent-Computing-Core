/* OS-0 bootstrap for the i386 PC BIOS. Linked at physical 0000:7c00.
 * Only real-mode diagnostic bring-up lives here; no ICC secrets or user data.
 */
.code16
.section .text,"ax",@progbits
.global _start
_start:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %ss
    movw $0x7000, %sp

    /* Own only the real-mode exception vectors we report. We never return. */
    movw $divide_fault, 0x00
    movw %ax, 0x02
    movw $invalid_opcode_fault, 0x18
    movw %ax, 0x1a

    call serial_init
    movw $boot_message, %si
    call serial_print

.if OS0_MODE == 0
    movw $ready_message, %si
    call serial_print
    jmp stop
.elseif OS0_MODE == 1
    movw $panic_message, %si
    jmp fatal
.elseif OS0_MODE == 2
    ud2
    /* If the fault is silently skipped, emit no success marker. */
    jmp stop
.else
    .error "OS0_MODE must be 0 (normal), 1 (panic), or 2 (invalid opcode)"
.endif

divide_fault:
    movw $divide_message, %si
    jmp fatal
invalid_opcode_fault:
    movw $invalid_opcode_message, %si
fatal:
    cli
    call serial_print
stop:
    cli
1:  hlt
    jmp 1b

/* 16550-compatible COM1, 115200 baud, 8N1, interrupt-free polled TX. */
serial_init:
    movw $0x3f9, %dx
    xorb %al, %al
    outb %al, %dx                 /* IER = 0 */
    movw $0x3fb, %dx
    movb $0x80, %al
    outb %al, %dx                 /* DLAB = 1 */
    movw $0x3f8, %dx
    movb $1, %al
    outb %al, %dx                 /* divisor low */
    movw $0x3f9, %dx
    xorb %al, %al
    outb %al, %dx                 /* divisor high */
    movw $0x3fb, %dx
    movb $3, %al
    outb %al, %dx                 /* DLAB = 0, 8N1 */
    movw $0x3fa, %dx
    movb $0xc7, %al
    outb %al, %dx                 /* FIFO reset/enable */
    movw $0x3fc, %dx
    movb $0x0b, %al
    outb %al, %dx                 /* modem control */
    ret

serial_print:
1:  lodsb
    testb %al, %al
    jz 2f
    call serial_putc
    jmp 1b
2:  ret

serial_putc:
    pushw %ax
    pushw %dx
    movb %al, %ah
    movw $0x3fd, %dx
1:  inb %dx, %al
    testb $0x20, %al
    jz 1b
    movw $0x3f8, %dx
    movb %ah, %al
    outb %al, %dx
    popw %dx
    popw %ax
    ret

boot_message:           .asciz "ICC OS0 BOOT\r\n"
ready_message:          .asciz "ICC OS0 READY\r\n"
panic_message:          .asciz "ICC OS0 PANIC MANUAL\r\n"
divide_message:         .asciz "ICC OS0 FAULT DE\r\n"
invalid_opcode_message: .asciz "ICC OS0 FAULT UD\r\n"

/* BIOS loads one sector and checks the signature at 510..511. */
.org 510
.word 0xaa55
