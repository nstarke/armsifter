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
#include <errno.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <capstone/capstone.h>

#define MEM_PATH "/proc/%ld/fd/%i"
#define HARNESS_FILE "harness"
#define IDX_FILE "start_idx"

unsigned char harness_file[] = {
  0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x54, 0x00, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00,
  0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x01, 0x00, 0x28, 0x00,
  0x04, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
  0x64, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
  0x00, 0x10, 0xa0, 0xe3, 0x00, 0x00, 0xa0, 0xe3, 0x01, 0x70, 0xa0, 0xe3,
  0x00, 0x00, 0x00, 0xef, 0x41, 0x11, 0x00, 0x00, 0x00, 0x61, 0x65, 0x61,
  0x62, 0x69, 0x00, 0x01, 0x07, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x2e,
  0x73, 0x68, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x2e, 0x74, 0x65,
  0x78, 0x74, 0x00, 0x2e, 0x41, 0x52, 0x4d, 0x2e, 0x61, 0x74, 0x74, 0x72,
  0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
  0x54, 0x00, 0x01, 0x00, 0x54, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x70,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
  0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x76, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned int harness_len = 312;

// https://gist.github.com/goblinhack/ca81294d76228de61d5199891a6abcc9
int execl_timed (int timeout_ms, int poll_ms, const char *cmd, ...) {
    pid_t child_pid;
    char *args[100];
    char *arg;
    const int maxargs = sizeof(args) / sizeof(args[0]);
    int argno = 0;
    va_list ap;
    int status;
    int cnt = 0;
    int w;


    va_start(ap, cmd);

    args[argno++] = (char*) cmd;
    while (argno < maxargs) {
        arg = va_arg(ap, char *);
        args[argno++] = arg;
        if (!arg) {
            break;
        }
    }
    va_end(ap);

    if (!argno || (argno >= maxargs)) {
        return (EINVAL);
    }

    child_pid = fork();
    if (child_pid == 0) {
        /*
         * child
         */
        execl(cmd, NULL);
        _exit(0);
    }

    if (child_pid < 0) {
        return (ENOMEM);
    }

    /*
     * parent
     */
    do {
        w = waitpid(child_pid, &status, WNOHANG);
        if (w == -1) {
            return (EINVAL);
        }

        usleep(poll_ms);

        if (w) {
            if (WIFEXITED(status) || WCOREDUMP(status)) {
                return (WEXITSTATUS(status));
            }
        }
    } while (cnt++ < (timeout_ms / poll_ms));
    
    printf("\nTimed out! Pid: %d\n", child_pid);

    return (ETIMEDOUT);
}

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

int check_dmesg_output() {
    char * dmesg_command = "dmesg | grep -i Backtrace";    
    FILE * fp = popen(dmesg_command, "r");
    int output_len = 0;
    int ch;

    if (!fp) {
        perror("cannot popen");
        return -1;
    }

    while((ch = fgetc(fp)) != EOF) {
        output_len++;
    }

    pclose(fp);
    return output_len;
}

int inject_instruction(int check_dmesg, char * addr, int idx, unsigned int instr, size_t size, int mem_holder, char * to_exec) {
    int status;
    
    memcpy(addr + idx, &instr, 4);

    status = write(mem_holder, addr, size);

    if (status == -1) {
        perror("write to memfd failed");
        return 1;
    }

    printf("\rNow Executing: %x", instr);

    if (execl_timed(2500, 100, to_exec, NULL) == -1) {
        // do something if execl died?
    }
    
    if (check_dmesg == 1){
        int r = check_dmesg_output();
        if (r > 0){
            printf("Dmesg returned Backtrace: %x", instr);
            exit(0);
        }
    }

    return 0;
}

void check_and_write_elf_file() {
    struct stat st;
    int status;
    FILE * harness;
    char buf[harness_len + 1];
    for (int i = 0; i < harness_len + 1; i++){
        buf[i] = harness_file[i];
    }

    snprintf(buf, harness_len + 1, "%s", harness_file);
    status = stat(HARNESS_FILE, &st);
    
    if (status == -1 || st.st_size == 0){
        printf("Writing harness file\n");
        harness = fopen(HARNESS_FILE, "wb");
        fwrite(buf, harness_len, 1, harness);
        fclose(harness);
    }
}

int main(int argc, char * argv[]) {
    int use_capstone = 0;
    int c;
    int idx;
    int status;
    int start_provided = 0;
    int end_provied = 0;
    char *addr;
    int template;
    int check_dmesg = 0;
    unsigned int pos_start = 0;
    unsigned int pos_end = 0;
    char position_value[9];
    struct stat st;
    csh handle;
	cs_insn *insn;
	size_t count;
    pid_t child;
    char instruction[5];
    int mem_holder;
    char to_exec[32];

    pid_t current_pid = getpid();

    while ((c = getopt (argc, argv, "acs:e:")) != -1) {
        switch (c) {
            case 'a':
                use_capstone = 1;
                break;
            case 'c':
                check_dmesg = 1;
                break;
            case 's':
                start_provided = 1;
                pos_start = strtoul(optarg, NULL, 16);
                break;
            case 'e':
                end_provied = 1;
                pos_end = strtoul(optarg, NULL, 16);
                break;
            default:
                exit(1);
        }
    }

    check_and_write_elf_file();

    status = stat(HARNESS_FILE, &st);
    if (status != 0) {
        perror("stat failed");
        return 1;
    }

    if (st.st_size == 0) {
        perror("problem writing harness file");
        return 1;
    }

    printf("Begin Process\n");

    template = open(HARNESS_FILE, O_RDWR);
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
            printf("offset not found - assemble and link 'harness'?\n");
            return 1;
        }

        write_idx_file(idx);
        printf("No revious start index found - start index file written.\n");
    } else {
        printf("Previous start index found\n");
    }

    printf("idx: %x\n", idx);

    sprintf(position_value, "%02X%02X%02X%02X", addr[idx+3], addr[idx+2], addr[idx+1], addr[idx]);

    if (start_provided == 0) {
        pos_start = strtoul(position_value, NULL, 16);
    }

    if (end_provied == 0) {
        pos_end = 0xffffffff;
    }

    printf("Starting at position: %x\nEnding at position: %x\n", pos_start, pos_end);

	if (use_capstone == 1 && cs_open(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        printf("Could not open Capstone\n");
        return -1;
    }
		
    mem_holder = syscall(SYS_memfd_create, "", MFD_CLOEXEC);
    if (mem_holder == -1) {
        perror("memfd_create failed");
        return 1;
    }

    sprintf(to_exec, MEM_PATH, current_pid, mem_holder);

    printf("exec path: %s\nuse_capstone: %d\ncheck_dmesg: %d\n", to_exec, use_capstone, check_dmesg);
    
    for (unsigned int i = pos_start; i <= pos_end; i++) {
        
        if (use_capstone == 1) {
            instruction[3] = (i >> 24) & 0xff;
            instruction[2] = (i >> 16) & 0xff;
            instruction[1] = (i >> 8) & 0xff;
            instruction[0] = i & 0xff;

            count = cs_disasm(handle, instruction, 4, 0, 0, &insn);
            if (count <= 0) {
                cs_free(insn, count);
                inject_instruction(check_dmesg, addr, idx, i, st.st_size, mem_holder, to_exec);
            }  else {
                cs_free(insn, count);
            }

        } else {
            inject_instruction(check_dmesg, addr, idx, i, st.st_size, mem_holder, to_exec);
        }
    }
    
    printf("\nEnding run\n");
    free(addr);
    cs_close(&handle);
    close(template);
    return 0;
}
