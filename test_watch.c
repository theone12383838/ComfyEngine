#include <stdio.h>
#include <unistd.h>

volatile int hp = 100;

int main() {
    printf("hp addr = %p\n", (void *)&hp);
    fflush(stdout);

    while (1) {
        hp++;
        usleep(10000);
    }
}
