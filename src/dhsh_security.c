#include "dhsh_security.h"
#include "dhsh.h"
#include <string.h>
#include <ctype.h>

// Validate command arguments for security
int dhsh_validate_args(char **args) {
    int arg_count = 0;
    
    // Count arguments and validate each one
    for (int i = 0; args[i] != NULL; i++) {
        arg_count++;
        
        // Check argument count
        if (arg_count > DHSH_MAX_ARGS) {
            fprintf(stderr, "dhsh: too many arguments (max %d)\n", DHSH_MAX_ARGS);
            return -1;
        }
        
        // Check argument length
        size_t arg_len = strlen(args[i]);
        if (arg_len > DHSH_MAX_CMD_LEN) {
            fprintf(stderr, "dhsh: argument too long (max %d characters)\n", DHSH_MAX_CMD_LEN);
            return -1;
        }
        
        // Check for null bytes (except at the end)
        for (size_t j = 0; j < arg_len; j++) {
            if (args[i][j] == '\0') {
                fprintf(stderr, "dhsh: invalid null byte in argument\n");
                return -1;
            }
        }
    }
    
    return 0;
}

// Sanitize environment variables
int dhsh_sanitize_env(const char *name, const char *value) {
    // Check name length
    if (strlen(name) > 255) {
        fprintf(stderr, "dhsh: environment variable name too long\n");
        return -1;
    }
    
    // Check value length
    if (strlen(value) > DHSH_MAX_ENV_SIZE) {
        fprintf(stderr, "dhsh: environment variable value too long\n");
        return -1;
    }
    
    // Check for valid variable name (alphanumeric and underscore only)
    for (const char *p = name; *p; p++) {
        if (!isalnum(*p) && *p != '_') {
            fprintf(stderr, "dhsh: invalid character in environment variable name\n");
            return -1;
        }
    }
    
    // Don't allow modification of critical environment variables
    const char *protected_vars[] = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "IFS", "BASH_ENV", "ENV", NULL
    };
    
    for (int i = 0; protected_vars[i] != NULL; i++) {
        if (strcmp(name, protected_vars[i]) == 0) {
            fprintf(stderr, "dhsh: cannot modify protected environment variable: %s\n", name);
            return -1;
        }
    }
    
    return 0;
}

// Apply seccomp filters to child processes
void dhsh_apply_child_seccomp(void) {
    // This is a basic seccomp filter that allows only essential syscalls
    // You can customize this based on your security requirements
    
    struct sock_filter filter[] = {
        // Load architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        
        // Check architecture (x86_64)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        
        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        
        // Allow essential syscalls
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_stat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fstat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lstat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lseek, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_munmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_brk, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigprocmask, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_access, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pipe, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_dup2, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getdents64, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getcwd, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chdir, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchdir, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_arch_prctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_set_tid_address, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_set_robust_list, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_futex, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_geteuid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getgid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getegid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prlimit64, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rseq, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // Default: kill the process
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };
    
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    
    // Apply the filter
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl(NO_NEW_PRIVS)");
        return;
    }
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        perror("prctl(SECCOMP)");
        return;
    }
}

// Maximum number of whitelisted commands
#define DHSH_MAX_WHITELIST 128

// Whitelist of allowed commands
const char *g_dhsh_whitelist[DHSH_MAX_WHITELIST] = {
    "cat", "cd", "clear", "date", "echo", "env", "export", "history",
    "help", "info", "jobs", "ls", "mkdir", "pwd", "rm", "rmdir",
    "sleep", "sort", "tail", "tee", "test", "time", "true", "false",
    "unset", "whoami", "uname", "ps", "top", "uptime", "who",
    "groups", "id", "hostid", "hostname", "seq", "tr", "wc",
    "head", "grep", "find", "which", "whereis", "type", "file",
    "stat", "touch", "cp", "mv", "ln", "chmod", "chown", "chgrp",
    "df", "du", "free", "kill", "ping", "ssh", "curl", "wget",
    "nano", "vi", "vim", "less", "more", "diff", "patch",
    "gzip", "gunzip", "tar", "zip", "unzip", "md5sum", "sha1sum",
    "sha256sum", "base64", "xxd", "hexdump", "od", "printf",
    "readlink", "realpath", "dirname", "basename", "mktemp",
    "shuf", "fold", "paste", "cut", "join", "uniq", "comm",
    "nl", "wc", "expand", "unexpand", "yes", "yes"
};

int g_dhsh_whitelist_count = 54;

// Set the whitelist from an array of command names
void dhsh_set_whitelist(const char **commands, int count) {
    // If count <= 0, allow all commands
    if (count <= 0) {
        g_dhsh_whitelist_count = -1; // Special value meaning "allow all"
        return;
    }

    if (count > DHSH_MAX_WHITELIST) {
        count = DHSH_MAX_WHITELIST;
    }
    g_dhsh_whitelist_count = count;
    for (int i = 0; i < count; i++) {
        g_dhsh_whitelist[i] = commands[i];
    }
}

// Check if a command is in the allowed list (optional whitelist)
int dhsh_is_command_allowed(const char *cmd) {
    // If whitelist is empty, allow all commands
    if (g_dhsh_whitelist_count <= 0) {
        return 1;
    }

    // Check if command is in whitelist
    for (int i = 0; i < g_dhsh_whitelist_count; i++) {
        if (strcmp(cmd, g_dhsh_whitelist[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

// Sanitize command line input to prevent injection attacks
int dhsh_sanitize_input(const char *line) {
    // Check for shell metacharacters that could be used for injection
    // Note: > and 2> are allowed because dhsh handles them as redirection
    const char *dangerous_chars = ";`|&$\n\r";

    for (const char *p = line; *p; p++) {
        // Check for dangerous characters
        for (const char *d = dangerous_chars; *d; d++) {
            if (*p == *d) {
                fprintf(stderr, "dhsh: dangerous character '%c' in input\n", *p);
                return -1;
            }
        }
    }

    return 0;
}