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
#include <sys/stat.h>

#define MEM_PATH "/proc/self/fd/%i"

#define IDX_FILE "start_idx"

unsigned int deny_list[] = { 
    0xebfffffe, 
    0x5ffffffe 
};

int find_index(char *data, size_t len) {
    size_t j = (len + (2 - 1)) / 2;
    // Magic OPCODE: e3a01000
    for (int i = 0; i < j; i += 2) {
        if (data[i] == 0x00 
        && data[i+1] == 0x10 
        && data[i+2] == 0xa0 
        && data[i+3] == 0xe3) {
            return i;
        }
    }

    return 0;
}

int check_idx_file() {
    unsigned int file_data;
    if (access(IDX_FILE, F_OK) == 0) {
        FILE *f = fopen(IDX_FILE, "r");    
        fread(&file_data, sizeof(int), 1, f);
        fclose(f);
        return file_data;
    } else {
        return -1;
    }
    
}

int write_idx_file(unsigned int idx) {
    FILE * f = fopen(IDX_FILE, "w");
    fwrite(&idx, sizeof(int), 1, f); 
    fclose(f);
    return 0;
}

int main(int argc, char * argv[]) {
    int idx;
    int status;
    char *addr;
    int template;
    unsigned int pos_start;
    unsigned int pos_end;
    char position_value[9];
    int mem_holder;
    char * to_exec;
    to_exec = malloc(32);
    pid_t child;
    struct stat st;
    status = stat("./hello", &st);

    if (status != 0) {
        perror("stat failed");
        return 1;
    }

    if (st.st_size == 0) {
        printf("Assemble and link hello.S");
        return 1;
    }

    printf("Begin Process\n");

    template = open("./hello", O_RDWR);
    if (template == -1) {
        perror("no template file");
        return 1;
    }

    addr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, template, 0);

    if (addr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    idx = check_idx_file();
    if (idx == -1){
        idx = find_index(addr, st.st_size);

        if (idx == 0) {
            printf("offset not found - assemble and link 'hello'?\n");
            return 1;
        }

        write_idx_file(idx);
        printf("No revious start index found - start index file written.\n");
    } else {
        printf("Previous start index found\n");
    }

    printf("idx: %x\n", idx);

    sprintf(position_value, "%02X%02X%02X%02X", addr[idx+3], addr[idx+2], addr[idx+1], addr[idx]);

    pos_start = strtoul(position_value, NULL, 16);

    pos_end = 0xffffffff;

    if (argv[1]) {
        pos_start = strtoul(argv[1], NULL, 16);
        if (argv[2]) {
            pos_end = strtoul(argv[2], NULL, 16);
        }
    }

    printf("Starting at position: %x\nEnding at position: %x\n", pos_start, pos_end);
    
    for (unsigned int i = pos_start; i > pos_end; i++) {
        if (i % 256 == 0){
            printf("\rNow Executing: %x", i);
        }

        int found = 0;
        for (int j = 0; j < sizeof(deny_list) / sizeof(int); j++ ) {
            if (i == deny_list[j]) {
                printf("Deny List: %x\n", deny_list[j]);
                found = 1;
                break;
            }
        }

        if (found == 1) {
            continue;
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
                status = write(mem_holder, addr, st.st_size);
                if (status == -1) {
                    perror("write to memfd failed");
                    return 1;
                }

                sprintf(to_exec, MEM_PATH, mem_holder);
                // printf("Executing: %s\n", to_exec);
                if (execl(to_exec, NULL) == -1) {
                   
                } 
                return 0;
            } else {
                wait(NULL);
            } 
        } else {
            perror("Fork failed");
            return 1;
        }
    }   
    
    printf("Ending run\n");
    close(template);
    free(to_exec);
    return 0;
}