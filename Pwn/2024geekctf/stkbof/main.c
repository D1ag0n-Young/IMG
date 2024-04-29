#include <stdio.h>
#include <unistd.h>

void stkbof() {
    char vul_buf[0x100];
    read(0, vul_buf, sizeof(vul_buf) + 16);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    puts("Do you know \"stack buffer overflow\"?");
    stkbof();
    return 0;
}
