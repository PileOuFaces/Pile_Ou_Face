/*
 * Intentionally vulnerable x86_64 ELF for ROP chain smoke tests.
 *
 * Compile (done automatically in Dockerfile):
 *   gcc -m64 -fno-stack-protector -no-pie -o vuln_x64.elf vuln.c
 *
 * Properties required by test_rop_build.py:
 *   - system() in PLT  (needed for ret2libc_x64)
 *   - exploitable stack buffer  (needed for ROP setup)
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Pull system() into PLT so angr can find it for ret2libc chains. */
void _pof_ref(void) { system("/bin/true"); }

/* Classic stack buffer overflow — no canary, no PIE. */
void vuln(const char *input) {
    char buf[64];
    strcpy(buf, input);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vuln(argv[1]);
    }
    return 0;
}
