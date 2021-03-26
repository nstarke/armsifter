#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <sys/wait.h>

#define HELLO_SIZE 312
#define MEM_PATH "/proc/self/fd/%i"

int main(int argc, char * argv[]) {
    int status;
    char *addr;
    int template;
    unsigned int pos;
    char position_value[9];
    int mem_holder;
    char * to_exec;
    to_exec = malloc(32);
    char trial_value[5];
    pid_t child;

    printf("Begin Process\n");

    template = open("./hello", O_RDWR);
    if (template == -1) {
        perror("no template file");
        return 1;
    }

    addr = mmap(NULL, HELLO_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, template, 0);

    if (addr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    sprintf(position_value, "%02X%02X%02X%02X", addr[0x57], addr[0x56], addr[0x55], addr[0x54]);
    pos = strtoul(position_value, NULL, 16);

    if (argv[1]) {
        pos = strtoul(argv[1], NULL, 16);
    }

    if (pos == 0) {
        pos = 0xffffffff;
    }

    printf("Starting at position: %x - %s\n", pos, position_value);
    
    for (unsigned int i = pos; i > 0; i--) {
        if (i % 256 == 0){
            printf("\rNow Executing: %x", i);
        }

        child = fork();
       
        if (child >= 0) {
            if (child == 0) {
                mem_holder = syscall(SYS_memfd_create, "", MFD_CLOEXEC);
                if (mem_holder == -1) {
                    perror("memfd_Create failed");
                    return 1;
                }
               
                memcpy(addr + 0x54, &i, 4);
                status = write(mem_holder, addr, HELLO_SIZE);
                if (status == -1) {
                    perror("write to memfd failed");
                    return 1;
                }

                sprintf(to_exec, MEM_PATH, mem_holder);
                // printf("Executing: %s\n", to_exec);
                if (execl(to_exec, NULL) == -1) {
                    perror("execl");
                }

                printf("Executed\n");
                return 0;
            } else {
                wait(NULL);
            } 
        } else {
            perror("Fork failed");
            return 1;
        }
    }   
    
    close(template);
    free(to_exec);
    return 0;
}