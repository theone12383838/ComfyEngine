#include <stdio.h>
#include <unistd.h>

volatile int hp = 100;

int main(void) {
    printf("PID: %d\n", getpid());
    printf("hp address: %p\n", (void *)&hp);
    fflush(stdout);

    while (1) {
        hp++;
        usleep(100000); // 100 ms
    }
    return 0;
}
