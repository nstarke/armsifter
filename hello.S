.data

.text

.globl _start
_start:
    /* syscall exit(int status) */
    mov     %r1, $0
    mov     %r0, $0     /* status := 0 */
    mov     %r7, $1     /* exit is syscall #1 */
    swi     $0          /* invoke syscall */
