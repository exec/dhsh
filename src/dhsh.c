#include "dhsh.h"
#include "dhsh_security.h"
#include <fcntl.h>
#include <termios.h> // For terminal control
#include <limits.h> // For PATH_MAX
#include <time.h> // For date/time functions
#include <ctype.h> // For isspace
#include <pwd.h> // For getpwuid

// Global history buffer
char *g_dhsh_history_commands[DHSH_HISTORY_SIZE];

// Circular buffer indices for O(1) insertion
int g_dhsh_history_count = 0;
int g_dhsh_history_head = 0;  // Index where next command will be written
int g_dhsh_history_tail = 0;  // Index of oldest entry
int g_dhsh_history_full = 0;  // Flag: buffer is full

// Global termios structures to save and restore terminal settings
static struct termios g_original_termios;
static struct termios g_raw_termios;

// Function to restore original terminal settings
void dhsh_restore_termios(void) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_original_termios);
}

// Signal handler for SIGINT (Ctrl+C)
// Uses write() instead of printf() for async-signal-safety
void dhsh_sigint_handler(int signo __attribute__((unused))) {
    // Write ^C to show the interrupt, just like bash
    // write() is async-signal-safe, unlike printf()
    const char signal_msg[] = "^C\n";
    if (write(STDOUT_FILENO, signal_msg, sizeof(signal_msg) - 1) < 0) {
        // Silently ignore write errors in signal handler
    }
    (void)signo; // Suppress unused parameter warning
}


// --- Built-in Command Implementations ---

// Forward declarations for built-in commands
int dhsh_cd(char **args);
int dhsh_help(char **args);
int dhsh_exit(char **args);
int dhsh_export(char **args);
int dhsh_unset(char **args);
int dhsh_history(char **args);
int dhsh_echo(char **args);
int dhsh_version(char **args);
int dhsh_info(char **args);
int dhsh_pwd(char **args);
int dhsh_env(char **args);
int dhsh_clear(char **args);
int dhsh_date(char **args);
int dhsh_whoami(char **args);
int dhsh_aliases(char **args);
int dhsh_jobs(char **args);
int dhsh_set_alias(char **args);
int dhsh_whitelist(char **args);
int dhsh_config(char **args);

// Built-in command: echo
int dhsh_echo(char **args) {
    if (args[1] == NULL) {
        printf("\n");
    } else {
        for (int i = 1; args[i] != NULL; i++) {
            printf("%s%s", args[i], (args[i+1] != NULL) ? " " : "");
        }
        printf("\n");
    }
    return 1;
}

// Array of built-in command names
char *builtin_str[] = {
    "cd",
    "help",
    "exit",
    "export",
    "unset",
    "history",
    "echo",
    "version",
    "info",
    "pwd",
    "env",
    "clear",
    "date",
    "whoami",
    "aliases",
    "alias",
    "jobs",
    "whitelist",
    "config"
};

// Array of corresponding built-in function pointers
int (*builtin_func[]) (char **) = {
    &dhsh_cd,
    &dhsh_help,
    &dhsh_exit,
    &dhsh_export,
    &dhsh_unset,
    &dhsh_history,
    &dhsh_echo,
    &dhsh_version,
    &dhsh_info,
    &dhsh_pwd,
    &dhsh_env,
    &dhsh_clear,
    &dhsh_date,
    &dhsh_whoami,
    &dhsh_aliases,
    &dhsh_aliases,
    &dhsh_jobs,
    &dhsh_whitelist,
    &dhsh_config
};

// Returns the number of built-in commands
int dhsh_num_builtins() {
    return sizeof(builtin_str) / sizeof(char *);
}

// Built-in command: change directory
int dhsh_cd(char **args) {
    if (args[1] == NULL) {
        fprintf(stderr, "dhsh: expected argument to \"cd\"\n");
    } else {
        // Validate path length
        if (strlen(args[1]) > PATH_MAX - 1) {
            fprintf(stderr, "dhsh: path too long\n");
            return 1;
        }
        
        // Resolve path to absolute path
        char resolved_path[PATH_MAX];
        if (realpath(args[1], resolved_path) == NULL) {
            // If realpath fails, it might be because the directory doesn't exist
            // Try to change directory anyway and let chdir handle the error
            if (chdir(args[1]) != 0) {
                perror("dhsh");
            }
        } else {
            // Use the resolved path for the actual change
            if (chdir(resolved_path) != 0) {
                perror("dhsh");
            }
        }
    }
    return 1; // Always continue the loop
}

// Built-in command: display help
int dhsh_help(char **args __attribute__((unused))) {
    printf("dhsh - The Dumb, Hardened Shell\n");
    printf("A minimalist, security-focused Linux shell.\n\n");
    printf("The following built-in commands are available:\n");
    for (int i = 0; i < dhsh_num_builtins(); i++) {
        printf("  %s\n", builtin_str[i]);
    }
    printf("\nAll other commands are executed via the system's PATH.\n");
    printf("Features like scripting are intentionally excluded for security. Piping and I/O redirection are supported.\n");
    return 1; // Always continue the loop
}

// Built-in command: exit shell
int dhsh_exit(char **args __attribute__((unused))) {
    return 0; // Signal to terminate the loop
}

// Built-in command: set environment variable
int dhsh_export(char **args) {
    if (args[1] == NULL) {
        fprintf(stderr, "dhsh: expected argument to \"export\" (e.g., VAR=value)\n");
    } else {
        char *name = strdup(args[1]); // Make a copy to modify
        if (!name) {
            perror("dhsh");
            return 1;
        }
        
        char *value = strchr(name, '=');
        if (value == NULL) {
            fprintf(stderr, "dhsh: export: invalid argument format. Use VAR=value\n");
            free(name);
        } else {
            *value = '\0'; // Null-terminate the name part
            value++; // Move past the '=' to the value part
            
            // Validate the environment variable
            if (dhsh_sanitize_env(name, value) == 0) {
                if (setenv(name, value, 1) != 0) { // Overwrite if exists
                    perror("dhsh");
                }
            }
            free(name);
        }
    }
    return 1;
}

// Built-in command: unset environment variable
int dhsh_unset(char **args) {
    if (args[1] == NULL) {
        fprintf(stderr, "dhsh: expected argument to \"unset\" (e.g., VAR)\n");
    } else {
        if (unsetenv(args[1]) != 0) {
            perror("dhsh");
        }
    }
    return 1;
}

// Built-in command: display history
int dhsh_history(char **args __attribute__((unused))) {
    if (g_dhsh_history_count == 0) {
        return 1;
    }

    // Iterate from tail to head, showing commands in order
    int index = g_dhsh_history_tail;
    int count = 0;

    while (count < g_dhsh_history_count) {
        if (g_dhsh_history_commands[index] != NULL) {
            printf("%d: %s\n", count, g_dhsh_history_commands[index]);
        }
        index = (index + 1) % DHSH_HISTORY_SIZE;
        count++;
    }
    return 1;
}

// Built-in command: display version
int dhsh_version(char **args __attribute__((unused))) {
    printf("%s\n", DHSH_VERSION_STRING);
    printf("Built on %s at %s\n", DHSH_BUILD_DATE, DHSH_BUILD_TIME);
    printf("Copyright (C) 2024 - The Dumb, Hardened Shell Project\n");
    printf("This is free software; see the source for copying conditions.\n");
    printf("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n");
    printf("PARTICULAR PURPOSE.\n");
    return 1;
}

// Built-in command: display shell information
int dhsh_info(char **args __attribute__((unused))) {
    printf("dhsh - The Dumb, Hardened Shell\n");
    printf("Version: %s\n", DHSH_VERSION);
    printf("Build: %s %s\n", DHSH_BUILD_DATE, DHSH_BUILD_TIME);
    printf("\nShell Information:\n");
    printf("  PID: %d\n", getpid());
    printf("  PPID: %d\n", getppid());
    
    // Get current working directory
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("  Working Directory: %s\n", cwd);
    }
    
    // Get user and host info
    char *user = getenv("USER");
    if (user) printf("  User: %s\n", user);
    
    char hostname[1024];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        printf("  Hostname: %s\n", hostname);
    }
    
    // Security features
    printf("\nSecurity Features:\n");
    printf("  - Input validation: ENABLED\n");
    printf("  - Protected environment variables: ENABLED\n");
    printf("  - Command length limit: %d bytes\n", DHSH_MAX_CMD_LEN);
    printf("  - Maximum arguments: %d\n", DHSH_MAX_ARGS);
    printf("  - History size: %d commands\n", DHSH_HISTORY_SIZE);
    printf("  - Seccomp filters: AVAILABLE (disabled by default)\n");
    
    // Compilation flags
    printf("\nCompilation Flags:\n");
    printf("  - FORTIFY_SOURCE: Level 3\n");
    printf("  - Stack Protector: STRONG\n");
    printf("  - Position Independent Executable: YES\n");
    printf("  - RELRO: FULL\n");
    
    return 1;
}

// Built-in command: display current directory
int dhsh_pwd(char **args __attribute__((unused))) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("%s\n", cwd);
    } else {
        fprintf(stderr, "dhsh: could not get current directory\n");
        return 1;
    }
    return 1;
}

// Built-in command: display environment variables
int dhsh_env(char **args __attribute__((unused))) {
    extern char **environ;
    for (int i = 0; environ[i] != NULL; i++) {
        printf("%s\n", environ[i]);
    }
    return 1;
}

// Built-in command: clear terminal screen
int dhsh_clear(char **args __attribute__((unused))) {
    printf("\x1b[2J\x1b[H");
    fflush(stdout);
    return 1;
}

// Built-in command: display current date/time
int dhsh_date(char **args __attribute__((unused))) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char buffer[256];
    strftime(buffer, sizeof(buffer), "%a %b %d %H:%M:%S %Z %Y", tm_info);
    printf("%s\n", buffer);
    return 1;
}

// Built-in command: display current user
int dhsh_whoami(char **args __attribute__((unused))) {
    char *user = getenv("USER");
    if (user) {
        printf("%s\n", user);
    } else {
        // Fallback to getpwuid
        struct passwd *pw;
        pw = getpwuid(getuid());
        if (pw) {
            printf("%s\n", pw->pw_name);
        } else {
            fprintf(stderr, "dhsh: could not determine user\n");
        }
    }
    return 1;
}

// Simple alias storage
#define MAX_ALIASES 32
#define MAX_ALIAS_NAME 64
#define MAX_ALIAS_VALUE 256

typedef struct {
    char name[MAX_ALIAS_NAME];
    char value[MAX_ALIAS_VALUE];
} alias_t;

static alias_t g_aliases[MAX_ALIASES];
static int g_alias_count = 0;

// Built-in command: manage/display aliases
int dhsh_aliases(char **args) {
    if (args[1] == NULL) {
        // Display all aliases
        for (int i = 0; i < g_alias_count; i++) {
            printf("%s='%s'\n", g_aliases[i].name, g_aliases[i].value);
        }
    } else {
        // Set an alias: alias name=value
        char *arg = args[1];
        char *eq = strchr(arg, '=');
        if (eq == NULL) {
            fprintf(stderr, "dhsh: alias: invalid format. Use: alias name=value\n");
            return 1;
        }

        if (g_alias_count >= MAX_ALIASES) {
            fprintf(stderr, "dhsh: alias: maximum aliases reached\n");
            return 1;
        }

        *eq = '\0';  // Split name and value
        const char *name = arg;
        const char *value = eq + 1;

        if (strlen(name) >= MAX_ALIAS_NAME) {
            fprintf(stderr, "dhsh: alias: name too long\n");
            return 1;
        }

        if (strlen(value) >= MAX_ALIAS_VALUE) {
            fprintf(stderr, "dhsh: alias: value too long\n");
            return 1;
        }

        strncpy(g_aliases[g_alias_count].name, name, MAX_ALIAS_NAME - 1);
        g_aliases[g_alias_count].name[MAX_ALIAS_NAME - 1] = '\0';

        // Strip leading and trailing quotes from value
        char *value_start = (char *)value;
        char *value_end = (char *)value + strlen(value) - 1;

        // Strip leading quotes
        while (*value_start == '"' || *value_start == '\'') {
            value_start++;
        }

        // Strip trailing quotes
        while (value_end > value_start && (*value_end == '"' || *value_end == '\'')) {
            *value_end = '\0';
            value_end--;
        }

        strncpy(g_aliases[g_alias_count].value, value_start, MAX_ALIAS_VALUE - 1);
        g_aliases[g_alias_count].value[MAX_ALIAS_VALUE - 1] = '\0';
        g_alias_count++;
    }
    return 1;
}

// Built-in command: display background jobs
int dhsh_jobs(char **args __attribute__((unused))) {
    // Note: This is a simplified implementation
    // A full implementation would track forked processes
    printf("No background jobs tracked.\n");
    return 1;
}

// Built-in command: set an alias (alternative to aliases)
int dhsh_set_alias(char **args) {
    if (args[1] == NULL || args[2] == NULL) {
        fprintf(stderr, "dhsh: alias: usage: alias name command\n");
        return 1;
    }

    if (g_alias_count >= MAX_ALIASES) {
        fprintf(stderr, "dhsh: alias: maximum aliases reached\n");
        return 1;
    }

    if (strlen(args[1]) >= MAX_ALIAS_NAME) {
        fprintf(stderr, "dhsh: alias: name too long\n");
        return 1;
    }

    // Join remaining args as the command value
    char value[MAX_ALIAS_VALUE] = {0};
    for (int i = 2; args[i] != NULL; i++) {
        if (i > 2) strncat(value, " ", MAX_ALIAS_VALUE - strlen(value) - 1);
        strncat(value, args[i], MAX_ALIAS_VALUE - strlen(value) - 1);
    }

    if (strlen(value) >= MAX_ALIAS_VALUE) {
        fprintf(stderr, "dhsh: alias: command too long\n");
        return 1;
    }

    strncpy(g_aliases[g_alias_count].name, args[1], MAX_ALIAS_NAME - 1);
    g_aliases[g_alias_count].name[MAX_ALIAS_NAME - 1] = '\0';
    strncpy(g_aliases[g_alias_count].value, value, MAX_ALIAS_VALUE - 1);
    g_aliases[g_alias_count].value[MAX_ALIAS_VALUE - 1] = '\0';
    g_alias_count++;

    return 1;
}

// Built-in command: manage whitelist of allowed commands
int dhsh_whitelist(char **args) {
    if (args[1] == NULL) {
        // Display whitelist
        printf("Whitelist contains %d commands:\n", g_dhsh_whitelist_count);
        for (int i = 0; i < g_dhsh_whitelist_count; i++) {
            printf("  %s\n", g_dhsh_whitelist[i]);
        }
    } else if (strcmp(args[1], "reset") == 0) {
        // Reset to default whitelist
        dhsh_set_whitelist(NULL, 0);
        printf("Whitelist reset to default.\n");
    } else if (strcmp(args[1], "add") == 0 && args[2] != NULL) {
        // Add command to whitelist
        const char *new_cmd = args[2];
        if (g_dhsh_whitelist_count < DHSH_MAX_WHITELIST) {
            g_dhsh_whitelist[g_dhsh_whitelist_count++] = new_cmd;
            printf("Added '%s' to whitelist.\n", new_cmd);
        } else {
            fprintf(stderr, "Whitelist is full (max %d commands)\n", DHSH_MAX_WHITELIST);
        }
    } else if (strcmp(args[1], "remove") == 0 && args[2] != NULL) {
        // Remove command from whitelist
        const char *remove_cmd = args[2];
        for (int i = 0; i < g_dhsh_whitelist_count; i++) {
            if (strcmp(g_dhsh_whitelist[i], remove_cmd) == 0) {
                // Shift remaining entries down
                for (int j = i; j < g_dhsh_whitelist_count - 1; j++) {
                    g_dhsh_whitelist[j] = g_dhsh_whitelist[j + 1];
                }
                g_dhsh_whitelist_count--;
                printf("Removed '%s' from whitelist.\n", remove_cmd);
                break;
            }
        }
    } else {
        fprintf(stderr, "Usage: whitelist [reset|add <cmd>|remove <cmd>]\n");
    }
    return 1;
}


// --- Core Shell Logic ---


// Launch a program and wait for it to terminate
int dhsh_launch(char **args) {
    pid_t pid;
    int status;

    pid = fork();
    if (pid == 0) {
        // Child process
        // Reset signal handlers to defaults
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);

        // Handle redirections
        if (dhsh_parse_redirections(&args) == -1) {
            _exit(EXIT_FAILURE);
        }

        // Apply seccomp filters for additional security
        // This restricts the child process to a safe set of syscalls
        dhsh_apply_child_seccomp();

        // execvp replaces the child process with the new program.
        // It only returns if an error occurs.
        if (execvp(args[0], args) == -1) {
            perror("dhsh");
        }
        // Use _exit() in child after fork() on exec error.
        // It terminates immediately without calling atexit() handlers.
        _exit(EXIT_FAILURE);
    } else if (pid < 0) {
        // Error forking
        perror("dhsh");
    } else {
        // Parent process
        // Wait for the child process to complete.
        do {
            waitpid(pid, &status, WUNTRACED);
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    return 1; // Signal to continue
}

// Launch a series of commands connected by pipes
// Launch a series of commands connected by pipes
int dhsh_launch_pipe(char **args, int num_pipes) {
    int num_commands = num_pipes + 1;
    char **commands[num_commands];
    int command_start = 0;
    int command_index = 0;

    // Split the arguments into commands
    for (int i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], "|") == 0) {
            args[i] = NULL;
            commands[command_index++] = &args[command_start];
            command_start = i + 1;
        }
    }
    commands[command_index] = &args[command_start];

    int pipefd[2];
    int in_fd = 0;
    pid_t pid;

    for (int i = 0; i < num_commands; i++) {
        if (pipe(pipefd) == -1) {
            perror("dhsh");
            return 1;
        }
        pid = fork();

        if (pid == 0) {
            // Child process
            // Reset SIGINT handler to default in child process
            signal(SIGINT, SIG_DFL);

            if (in_fd != 0) {
                dup2(in_fd, 0);
                close(in_fd);
            }
            if (i < num_commands - 1) {
                dup2(pipefd[1], 1);
                close(pipefd[1]);
            }
            close(pipefd[0]);

            // Handle redirections for each command in the pipe
            if (dhsh_parse_redirections(&commands[i]) == -1) {
                _exit(EXIT_FAILURE);
            }

            execvp(commands[i][0], commands[i]);
            perror("dhsh");
            _exit(EXIT_FAILURE);
        } else if (pid < 0) {
            perror("dhsh");
            return 1;
        }

        // Parent process
        int status;
        waitpid(pid, &status, 0);
        close(pipefd[1]);
        in_fd = pipefd[0];
    }

    return 1;
}

// Parse redirection operators and apply them to current process file descriptors.
// Returns the number of redirections found, or -1 on error.
// Does NOT modify the args array - it only modifies fd's.
int dhsh_apply_redirections(char **args) {
    int redirect_count = 0;
    int fd;
    int skip_next = 0;

    for (int i = 0; args[i] != NULL; i++) {
        if (skip_next) {
            skip_next = 0;
            continue;
        }

        if (strcmp(args[i], ">") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
            redirect_count++;
            skip_next = 1;
        } else if (strcmp(args[i], ">>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
            redirect_count++;
            skip_next = 1;
        } else if (strcmp(args[i], "<") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_RDONLY);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
            redirect_count++;
            skip_next = 1;
        } else if (strcmp(args[i], "2>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDERR_FILENO);
            close(fd);
            redirect_count++;
            skip_next = 1;
        } else if (strcmp(args[i], "&>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
            redirect_count++;
            skip_next = 1;
        }
    }

    return redirect_count;
}

// Parse redirections for external command execution.
// Returns 0 on success, -1 on error.
// Modifies args to remove redirection tokens.
int dhsh_apply_redirections_and_clean_args(char **args) {
    int fd;
    int skip_next = 0;
    int i, j;

    // First, apply redirections
    for (i = 0; args[i] != NULL; i++) {
        if (skip_next) {
            skip_next = 0;
            continue;
        }

        if (strcmp(args[i], ">") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
            skip_next = 1;
        } else if (strcmp(args[i], ">>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
            skip_next = 1;
        } else if (strcmp(args[i], "<") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_RDONLY);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
            skip_next = 1;
        } else if (strcmp(args[i], "2>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDERR_FILENO);
            close(fd);
            skip_next = 1;
        } else if (strcmp(args[i], "&>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
            skip_next = 1;
        }
    }

    // Now clean up args (remove redirection tokens)
    for (i = 0, j = 0; args[i] != NULL; i++) {
        if (skip_next) {
            skip_next = 0;
            continue;
        }

        if (strcmp(args[i], ">") == 0) {
            skip_next = 1;
        } else if (strcmp(args[i], ">>") == 0) {
            skip_next = 1;
        } else if (strcmp(args[i], "<") == 0) {
            skip_next = 1;
        } else if (strcmp(args[i], "2>") == 0) {
            skip_next = 1;
        } else if (strcmp(args[i], "&>") == 0) {
            skip_next = 1;
        } else {
            args[j++] = args[i];
        }
    }
    args[j] = NULL;
    return 0;
}

// Parses redirection operators and their files from the arguments.
// Modifies the args array in place to remove redirection tokens and files.
int dhsh_parse_redirections(char ***args_ptr) {
    char **args = *args_ptr;
    int i, j;
    int fd;

    for (i = 0, j = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], ">") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
            i++; // Skip filename
        } else if (strcmp(args[i], ">>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
            i++; // Skip filename
        } else if (strcmp(args[i], "<") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_RDONLY);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
            i++; // Skip filename
        } else if (strcmp(args[i], "2>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDERR_FILENO);
            close(fd);
            i++; // Skip filename
        } else if (strcmp(args[i], "&>") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing file for redirection\n");
                return -1;
            }
            fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("dhsh");
                return -1;
            }
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
            i++; // Skip filename
        } else {
            args[j++] = args[i];
        }
    }
    args[j] = NULL; // Null-terminate the new args array
    return 0;
}

// Read heredoc content from stdin until delimiter is found
// Returns dynamically allocated string with heredoc content
static char *dhsh_read_heredoc(const char *delimiter) {
    char *buffer = malloc(DHSH_RL_BUFSIZE);
    if (!buffer) {
        fprintf(stderr, "dhsh: memory allocation error\n");
        return NULL;
    }

    int bufsize = DHSH_RL_BUFSIZE;
    int pos = 0;

    while (1) {
        int c = getchar();

        if (c == EOF) {
            break;
        }

        if (c == '\n') {
            // Check if the current line matches the delimiter
            char line[DHSH_RL_BUFSIZE];
            int line_pos = 0;

            // Read the rest of the line
            while ((c = getchar()) != '\n' && c != EOF && line_pos < DHSH_RL_BUFSIZE - 1) {
                line[line_pos++] = c;
            }
            line[line_pos] = '\0';

            // Trim whitespace from line
            while (line_pos > 0 && isspace((unsigned char)line[line_pos - 1])) {
                line[--line_pos] = '\0';
            }

            // Trim leading whitespace from delimiter for comparison
            const char *delim_ptr = delimiter;
            while (*delim_ptr && isspace((unsigned char)*delim_ptr)) {
                delim_ptr++;
            }

            // Compare
            if (strncmp(line, delim_ptr, strlen(delim_ptr)) == 0 &&
                (line[strlen(delim_ptr)] == '\0' || isspace((unsigned char)line[strlen(delim_ptr)]))) {
                break;
            }

            // Add the line plus newline to the buffer
            if (pos + line_pos + 1 >= bufsize) {
                bufsize = bufsize * 2 + line_pos + 2;
                buffer = realloc(buffer, bufsize);
                if (!buffer) {
                    fprintf(stderr, "dhsh: memory allocation error\n");
                    return NULL;
                }
            }

            memcpy(buffer + pos, line, line_pos);
            buffer[pos + line_pos] = '\n';
            pos += line_pos + 1;
        }
    }

    buffer[pos] = '\0';
    return buffer;
}

// Handle heredoc redirection - reads content from stdin and writes to temp file
// Returns 0 on success, -1 on error
int dhsh_handle_heredoc(char **args, int *fd_out) {
    for (int i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], "<<") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "dhsh: syntax error: missing heredoc delimiter\n");
                return -1;
            }
            const char *delimiter = args[i+1];
            i++; // Skip delimiter

            // Read heredoc content
            char *heredoc = dhsh_read_heredoc(delimiter);
            if (!heredoc) {
                return -1;
            }

            // Create temp file for heredoc content
            FILE *tmp = tmpfile();
            if (!tmp) {
                fprintf(stderr, "dhsh: could not create temp file for heredoc\n");
                free(heredoc);
                return -1;
            }

            fwrite(heredoc, 1, strlen(heredoc), tmp);
            free(heredoc);
            rewind(tmp);

            *fd_out = fileno(tmp);
            dup2(*fd_out, STDIN_FILENO);
            close(*fd_out);

            // Clean up args by removing << and delimiter
            int j = 0;
            for (int k = 0; args[k] != NULL; k++) {
                if (strcmp(args[k], "<<") == 0) {
                    k++; // Skip delimiter too
                    continue;
                }
                args[j++] = args[k];
            }
            args[j] = NULL;

            return 0;
        }
    }
    return -1; // No heredoc found
}

// Execute shell built-in or launch program
int dhsh_execute(char **args, const char *original_line) {
    // Sanitize input to prevent injection attacks
    if (dhsh_sanitize_input(original_line) != 0) {
        return 1; // Continue loop but don't execute
    }

    if (args[0] == NULL) {
        // An empty command was entered.
        return 1;
    }

    // Validate arguments for security
    if (dhsh_validate_args(args) != 0) {
        return 1; // Continue loop but don't execute
    }

    // Check for pipes
    int num_pipes = 0;
    for (int i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], "|") == 0) {
            num_pipes++;
        }
    }

    if (num_pipes > 0) {
        return dhsh_launch_pipe(args, num_pipes);
    }

    // Check for heredoc
    int heredoc_fd = -1;
    if (dhsh_handle_heredoc(args, &heredoc_fd) == 0) {
        // Heredoc was handled, now apply other redirections
        if (dhsh_apply_redirections_and_clean_args(args) != 0) {
            return 1; // Continue loop on error
        }
    } else {
        // No heredoc, apply standard redirections
        if (dhsh_apply_redirections_and_clean_args(args) != 0) {
            return 1; // Continue loop on error
        }
    }

    // Check if the command is a built-in
    for (int i = 0; i < dhsh_num_builtins(); i++) {
        if (strcmp(args[0], builtin_str[i]) == 0) {
            // For builtins, we need to apply redirections first
            if (dhsh_apply_redirections_and_clean_args(args) == 0) {
                return (*builtin_func[i])(args);
            }
            return 1; // Continue loop on error
        }
    }

    // Check if command is allowed (optional whitelist)
    if (!dhsh_is_command_allowed(args[0])) {
        fprintf(stderr, "dhsh: command not allowed: %s\n", args[0]);
        return 1;
    }

    // If not a built-in, launch it as an external command
    return dhsh_launch(args);
}

// Read a line from stdin, handling dynamic resizing and basic line editing




// Read a line from stdin with proper bounds checking and input validation
char *dhsh_read_line(void) {
    static char buffer[DHSH_RL_BUFSIZE];
    int position = 0;
    int c;
    int history_index = g_dhsh_history_count;
    
    
    while (1) {
        c = getchar();
        
        if (c == EOF) {
            // Handle EOF (Ctrl+D)
            if (position == 0) {
                return NULL;
            } else {
                // If there's input, treat as newline
                c = '\n';
            }
        }
        
        if (c == '\n') {
            buffer[position] = '\0';
            // Restore terminal for newline
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_original_termios);
            printf("\n");
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_raw_termios);
            return strdup(buffer);
        }
        
        // Handle escape sequences for arrow keys
        if (c == DHSH_ESC_SEQ_START) {
            char seq[3];
            if (read(STDIN_FILENO, &seq[0], 1) != 1) continue;
            if (read(STDIN_FILENO, &seq[1], 1) != 1) continue;
            
            if (seq[0] == '[') {
                switch (seq[1]) {
                    case 'A': // Up arrow
                        if (history_index > 0) {
                            history_index--;
                            // Clear current line
                            printf("\r%s", DHSH_CLEAR_LINE);
                            // Reprint prompt
                            char cwd[1024];
                            char *user = getenv("USER") ? getenv("USER") : "user";
                            char hostname[1024];
                            gethostname(hostname, 1024);
                            if (getcwd(cwd, sizeof(cwd))) {
                                printf("%s%s@%s %s%s%s$ ", DHSH_COLOR_WHITE, user, hostname, 
                                       DHSH_COLOR_CYAN, cwd, DHSH_COLOR_RESET);
                            }
                            // Copy history to buffer
                            strncpy(buffer, g_dhsh_history_commands[history_index], DHSH_RL_BUFSIZE - 1);
                            buffer[DHSH_RL_BUFSIZE - 1] = '\0';
                            position = strlen(buffer);
                            printf("%s", buffer);
                            fflush(stdout);
                        }
                        break;
                    case 'B': // Down arrow
                        if (history_index < g_dhsh_history_count - 1) {
                            history_index++;
                            // Clear current line
                            printf("\r%s", DHSH_CLEAR_LINE);
                            // Reprint prompt
                            char cwd[1024];
                            char *user = getenv("USER") ? getenv("USER") : "user";
                            char hostname[1024];
                            gethostname(hostname, 1024);
                            if (getcwd(cwd, sizeof(cwd))) {
                                printf("%s%s@%s %s%s%s$ ", DHSH_COLOR_WHITE, user, hostname, 
                                       DHSH_COLOR_CYAN, cwd, DHSH_COLOR_RESET);
                            }
                            // Copy history to buffer
                            strncpy(buffer, g_dhsh_history_commands[history_index], DHSH_RL_BUFSIZE - 1);
                            buffer[DHSH_RL_BUFSIZE - 1] = '\0';
                            position = strlen(buffer);
                            printf("%s", buffer);
                            fflush(stdout);
                        } else if (history_index == g_dhsh_history_count - 1) {
                            history_index++;
                            // Clear line and show empty prompt
                            printf("\r%s", DHSH_CLEAR_LINE);
                            char cwd[1024];
                            char *user = getenv("USER") ? getenv("USER") : "user";
                            char hostname[1024];
                            gethostname(hostname, 1024);
                            if (getcwd(cwd, sizeof(cwd))) {
                                printf("%s%s@%s %s%s%s$ ", DHSH_COLOR_WHITE, user, hostname, 
                                       DHSH_COLOR_CYAN, cwd, DHSH_COLOR_RESET);
                            }
                            buffer[0] = '\0';
                            position = 0;
                            fflush(stdout);
                        }
                        break;
                }
            }
            continue;
        }
        
        // Handle backspace
        if (c == 127 || c == '\b') {
            if (position > 0) {
                position--;
                buffer[position] = '\0';
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        
        // Handle Ctrl+C (already handled by signal handler)
        if (c == 3) {
            buffer[0] = '\0';
            position = 0;
            continue;
        }
        
        // Handle Ctrl+U (clear line)
        if (c == 21) {
            while (position > 0) {
                position--;
                printf("\b \b");
            }
            buffer[0] = '\0';
            fflush(stdout);
            continue;
        }
        
        // Only accept printable characters and prevent buffer overflow
        if (c >= 32 && c <= 126 && position < DHSH_RL_BUFSIZE - 1) {
            buffer[position] = c;
            position++;
            buffer[position] = '\0';
            putchar(c);
            fflush(stdout);
        }
    }
}

char **dhsh_split_line(char *line) {
    int bufsize = DHSH_TOK_BUFSIZE;
    int position = 0;
    char **tokens = malloc(bufsize * sizeof(char*));
    char *token;
    char *line_ptr = line; // Pointer for strsep

    // Check if malloc succeeded
    if (!tokens) {
        fprintf(stderr, "dhsh: allocation error\n");
        exit(EXIT_FAILURE);
    }

    // strsep modifies the string, so we use a pointer to it
    while ((token = strsep(&line_ptr, DHSH_TOK_DELIM)) != NULL) {
        // Skip empty tokens resulting from multiple delimiters
        if (*token == '\0') {
            continue;
        }
        tokens[position] = token;
        position++;

        if (position >= bufsize) {
            bufsize += DHSH_TOK_BUFSIZE;
            tokens = realloc(tokens, bufsize * sizeof(char*));
            // Check if realloc succeeded
            if (!tokens) {
                fprintf(stderr, "dhsh: allocation error\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    tokens[position] = NULL; // Null-terminate the array of tokens
    return tokens;
}

// Alternative version of dhsh_split_line that handles heredoc operators
// This is used when we need to detect << and >> operators
char **dhsh_split_line_heredoc(char *line) {
    int bufsize = DHSH_TOK_BUFSIZE;
    int position = 0;
    char **tokens = malloc(bufsize * sizeof(char*));
    char *line_ptr = line;

    if (!tokens) {
        fprintf(stderr, "dhsh: allocation error\n");
        exit(EXIT_FAILURE);
    }

    // Simple parsing that handles << and >> specially
    while (*line_ptr) {
        // Skip whitespace
        while (*line_ptr == ' ' || *line_ptr == '\t' || *line_ptr == '\r' || *line_ptr == '\n') {
            line_ptr++;
        }

        if (*line_ptr == '\0') {
            break;
        }

        // Check for heredoc operator <<
        if (line_ptr[0] == '<' && line_ptr[1] == '<') {
            tokens[position] = "<<";
            position++;
            line_ptr += 2;
            // Get the delimiter (up to whitespace or end)
            char *start = line_ptr;
            while (*line_ptr && *line_ptr != ' ' && *line_ptr != '\t' && *line_ptr != '\r' && *line_ptr != '\n') {
                line_ptr++;
            }
            if (position >= bufsize) {
                bufsize += DHSH_TOK_BUFSIZE;
                tokens = realloc(tokens, bufsize * sizeof(char*));
                if (!tokens) {
                    fprintf(stderr, "dhsh: allocation error\n");
                    exit(EXIT_FAILURE);
                }
            }
            tokens[position] = start;
            *line_ptr = '\0';
            line_ptr++;
            position++;
            continue;
        }

        // Check for append operator >>
        if (line_ptr[0] == '>' && line_ptr[1] == '>') {
            tokens[position] = ">>";
            position++;
            line_ptr += 2;
            // Get the filename (up to whitespace or end)
            char *start = line_ptr;
            while (*line_ptr && *line_ptr != ' ' && *line_ptr != '\t' && *line_ptr != '\r' && *line_ptr != '\n') {
                line_ptr++;
            }
            if (position >= bufsize) {
                bufsize += DHSH_TOK_BUFSIZE;
                tokens = realloc(tokens, bufsize * sizeof(char*));
                if (!tokens) {
                    fprintf(stderr, "dhsh: allocation error\n");
                    exit(EXIT_FAILURE);
                }
            }
            tokens[position] = start;
            *line_ptr = '\0';
            line_ptr++;
            position++;
            continue;
        }

        // Regular token (up to whitespace)
        char *start = line_ptr;
        while (*line_ptr && *line_ptr != ' ' && *line_ptr != '\t' && *line_ptr != '\r' && *line_ptr != '\n') {
            line_ptr++;
        }
        if (position >= bufsize) {
            bufsize += DHSH_TOK_BUFSIZE;
            tokens = realloc(tokens, bufsize * sizeof(char*));
            if (!tokens) {
                fprintf(stderr, "dhsh: allocation error\n");
                exit(EXIT_FAILURE);
            }
        }
        tokens[position] = start;
        if (*line_ptr) {
            *line_ptr = '\0';
            line_ptr++;
        }
        position++;
    }

    tokens[position] = NULL;
    return tokens;
}

// Split a line into commands (separated by '|')
char **dhsh_split_line_pipe(char *line) {
    int bufsize = DHSH_TOK_BUFSIZE;
    int position = 0;
    char **tokens = malloc(bufsize * sizeof(char*));
    char *token;
    char *line_ptr = line; // Pointer for strsep

    // Check if malloc succeeded
    if (!tokens) {
        fprintf(stderr, "dhsh: allocation error\n");
        exit(EXIT_FAILURE);
    }

    // strsep modifies the string, so we use a pointer to it
    while ((token = strsep(&line_ptr, "|")) != NULL) {
        // Trim leading and trailing whitespace
        while (*token == ' ' || *token == '\t' || *token == '\n' || *token == '\r') {
            token++;
        }
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
            *end = '\0';
            end--;
        }

        // Skip empty tokens resulting from multiple delimiters or trimming
        if (*token == '\0') {
            continue;
        }
        tokens[position] = token;
        position++;

        if (position >= bufsize) {
            bufsize += DHSH_TOK_BUFSIZE;
            tokens = realloc(tokens, bufsize * sizeof(char*));
            // Check if realloc succeeded
            if (!tokens) {
                fprintf(stderr, "dhsh: allocation error\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    tokens[position] = NULL; // Null-terminate the array of tokens
    return tokens;
}

// Main shell loop
void dhsh_loop(void) {
    char *line;
    char **args;
    int status;
    char cwd[1024];
    char *user;
    char *host;

    // Initialize circular buffer state
    g_dhsh_history_head = 0;
    g_dhsh_history_tail = 0;
    g_dhsh_history_count = 0;
    g_dhsh_history_full = 0;

    // Set up signal handler for SIGINT
    signal(SIGINT, dhsh_sigint_handler);

    user = getenv("USER");
    if (!user) user = "user";

    char hostname[1024];
    gethostname(hostname, 1024);
    host = hostname;
    if (!host) host = "localhost";

    do {
        // Get current working directory for the prompt
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
             printf("%s%s@%s %s%s%s$ ", DHSH_COLOR_WHITE, user, host, DHSH_COLOR_CYAN, cwd, DHSH_COLOR_RESET);
        } else {
            // Fallback prompt if getcwd fails
            printf("%s%s@%s %s?%s$ ", DHSH_COLOR_WHITE, user, host, DHSH_COLOR_CYAN, DHSH_COLOR_RESET);
        }

        line = dhsh_read_line();
        if (line == NULL) { // Handle EOF
            status = 0;
            printf("\n");
        } else {
            // Store command in circular buffer
            // Free the existing command at this position if buffer is full
            // Buffer is full when count == DHSH_HISTORY_SIZE
            if (g_dhsh_history_count == DHSH_HISTORY_SIZE) {
                free(g_dhsh_history_commands[g_dhsh_history_tail]);
                g_dhsh_history_tail = (g_dhsh_history_tail + 1) % DHSH_HISTORY_SIZE;
                g_dhsh_history_full = 1;
            }

            // Store new command at head position
            g_dhsh_history_commands[g_dhsh_history_head] = strdup(line);

            // Update head pointer
            g_dhsh_history_head = (g_dhsh_history_head + 1) % DHSH_HISTORY_SIZE;

            // Update count
            if (g_dhsh_history_count < DHSH_HISTORY_SIZE) {
                g_dhsh_history_count++;
            }

            args = dhsh_split_line(line);
            status = dhsh_execute(args, line);
            free(line);
            free(args);
        }
    } while (status);
}

// --- Main Entry Point ---

// Cleanup function to free all history
void dhsh_cleanup_history(void) {
    if (g_dhsh_history_count == 0) {
        return;
    }

    int index = g_dhsh_history_tail;
    int count = 0;

    while (count < g_dhsh_history_count) {
        if (g_dhsh_history_commands[index] != NULL) {
            free(g_dhsh_history_commands[index]);
            g_dhsh_history_commands[index] = NULL;
        }
        index = (index + 1) % DHSH_HISTORY_SIZE;
        count++;
    }

    g_dhsh_history_count = 0;
    g_dhsh_history_head = 0;
    g_dhsh_history_tail = 0;
    g_dhsh_history_full = 0;
}

int main(int argc, char **argv) {
    // Handle command-line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
            printf("%s\n", DHSH_VERSION_STRING);
            printf("Built on %s at %s\n", DHSH_BUILD_DATE, DHSH_BUILD_TIME);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -h, --help     Display this help message\n");
            printf("  -v, --version  Display version information\n");
            printf("  -c <config>    Use config file (default: ~/.dhshrc)\n");
            printf("\nBuilt-in commands:\n");
            printf("  cd, help, exit, export, unset, history, echo, version, info, config\n");
            return EXIT_SUCCESS;
        } else if (strcmp(argv[1], "-c") == 0 && argc > 2) {
            // Use specified config file
            dhsh_init_config(argv[2]);
            // Continue to shell
        } else {
            fprintf(stderr, "dhsh: unknown option: %s\n", argv[1]);
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    // Save original terminal settings
    tcgetattr(STDIN_FILENO, &g_original_termios);
    atexit(dhsh_restore_termios); // Ensure settings are restored on exit
    atexit(dhsh_cleanup_history); // Ensure history is freed on exit

    // Set terminal to raw mode
    g_raw_termios = g_original_termios;
    g_raw_termios.c_lflag &= ~(ICANON | ECHO); // Disable canonical mode and echoing
    g_raw_termios.c_cc[VMIN] = 1;  // Read 1 character at a time
    g_raw_termios.c_cc[VTIME] = 0; // No timeout
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_raw_termios);

    // Load configuration from config file
    dhsh_init_config(NULL);  // NULL uses default path

    // Run the command loop.
    dhsh_loop();

    // Perform any shutdown/cleanup.
    return EXIT_SUCCESS;
}

// ============================================================================
// Configuration File Parser
// ============================================================================

#include <ctype.h>

// Configuration value types
typedef enum {
    DHSH_CONFIG_STRING,
    DHSH_CONFIG_INT,
    DHSH_CONFIG_BOOL
} dhsh_config_type_t;

// Configuration entry
typedef struct {
    char name[64];
    dhsh_config_type_t type;
    union {
        char *str_val;
        int int_val;
        int bool_val;
    } value;
    char *default_value;  // String representation of default
} config_entry_t;

// Maximum number of config entries
#define DHSH_MAX_CONFIG_ENTRIES 128

// Global config storage
static config_entry_t g_config_entries[DHSH_MAX_CONFIG_ENTRIES];
static int g_config_count = 0;

// Default config values (as string representations)
static const char *g_default_values[DHSH_MAX_CONFIG_ENTRIES];
static int g_default_count = 0;

// Forward declarations
static void dhsh_config_set_string(const char *name, const char *value);
static void dhsh_config_set_int(const char *name, int value);
static void dhsh_config_set_bool(const char *name, int value);

// Add a string configuration entry
static void dhsh_config_add_string(const char *name, const char *value, const char *default_val) {
    if (g_config_count >= DHSH_MAX_CONFIG_ENTRIES) return;

    strncpy(g_config_entries[g_config_count].name, name, 63);
    g_config_entries[g_config_count].name[63] = '\0';
    g_config_entries[g_config_count].type = DHSH_CONFIG_STRING;
    g_config_entries[g_config_count].value.str_val = strdup(value);
    g_config_entries[g_config_count].default_value = strdup(default_val);
    g_config_count++;
}

// Add an integer configuration entry
static void dhsh_config_add_int(const char *name, int value, const char *default_val) {
    if (g_config_count >= DHSH_MAX_CONFIG_ENTRIES) return;

    strncpy(g_config_entries[g_config_count].name, name, 63);
    g_config_entries[g_config_count].name[63] = '\0';
    g_config_entries[g_config_count].type = DHSH_CONFIG_INT;
    g_config_entries[g_config_count].value.int_val = value;
    g_config_entries[g_config_count].default_value = strdup(default_val);
    g_config_count++;
}

// Add a boolean configuration entry
static void dhsh_config_add_bool(const char *name, int value, const char *default_val) {
    if (g_config_count >= DHSH_MAX_CONFIG_ENTRIES) return;

    strncpy(g_config_entries[g_config_count].name, name, 63);
    g_config_entries[g_config_count].name[63] = '\0';
    g_config_entries[g_config_count].type = DHSH_CONFIG_BOOL;
    g_config_entries[g_config_count].value.bool_val = value;
    g_config_entries[g_config_count].default_value = strdup(default_val);
    g_config_count++;
}

// Get a configuration entry by name
static config_entry_t *dhsh_config_find(const char *name) {
    for (int i = 0; i < g_config_count; i++) {
        if (strcmp(g_config_entries[i].name, name) == 0) {
            return &g_config_entries[i];
        }
    }
    return NULL;
}

// Set a string configuration value
static void dhsh_config_set_string(const char *name, const char *value) {
    config_entry_t *entry = dhsh_config_find(name);
    if (entry && entry->type == DHSH_CONFIG_STRING) {
        free(entry->value.str_val);
        entry->value.str_val = strdup(value);
    }
}

// Set an integer configuration value
static void dhsh_config_set_int(const char *name, int value) {
    config_entry_t *entry = dhsh_config_find(name);
    if (entry && entry->type == DHSH_CONFIG_INT) {
        entry->value.int_val = value;
    }
}

// Set a boolean configuration value
static void dhsh_config_set_bool(const char *name, int value) {
    config_entry_t *entry = dhsh_config_find(name);
    if (entry && entry->type == DHSH_CONFIG_BOOL) {
        entry->value.bool_val = value ? 1 : 0;
    }
}

// Trim whitespace from string
static char *trim_whitespace(char *str) {
    if (!str) return str;

    // Trim leading
    while (*str && isspace((unsigned char)*str)) str++;

    if (*str == '\0') return str;

    // Trim trailing
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return str;
}

// Parse a boolean value from string
static int parse_bool(const char *str) {
    if (!str) return 0;
    str = trim_whitespace((char *)str);

    // Check for ON/TRUE/YES (case-insensitive)
    if (strcasecmp(str, "ON") == 0 || strcasecmp(str, "TRUE") == 0 ||
        strcasecmp(str, "YES") == 0 || strcasecmp(str, "1") == 0) {
        return 1;
    }
    // Check for OFF/FALSE/NO (case-insensitive)
    if (strcasecmp(str, "OFF") == 0 || strcasecmp(str, "FALSE") == 0 ||
        strcasecmp(str, "NO") == 0 || strcasecmp(str, "0") == 0) {
        return 0;
    }
    return 0;  // Default to OFF for invalid values
}

// Initialize configuration from file
int dhsh_init_config(const char *config_path) {
    // Set default config values first
    // Core behaviors
    dhsh_config_add_bool("history", 1, "ON");
    dhsh_config_add_int("history_size", 100, "100");
    dhsh_config_add_bool("line_editing", 1, "ON");
    dhsh_config_add_bool("colorful_prompt", 1, "ON");

    // Input validation
    dhsh_config_add_int("max_cmd_length", 4096, "4096");
    dhsh_config_add_int("max_args", 256, "256");
    dhsh_config_add_int("max_arg_length", 1024, "1024");

    // Environment protection
    dhsh_config_add_bool("protect_env", 1, "ON");

    // Redirection
    dhsh_config_add_bool("redir_stdout", 1, "ON");
    dhsh_config_add_bool("redir_append", 1, "ON");
    dhsh_config_add_bool("redir_input", 1, "ON");
    dhsh_config_add_bool("redir_stderr", 1, "ON");
    dhsh_config_add_bool("redir_both", 1, "ON");

    // Pipelines
    dhsh_config_add_bool("pipelines", 1, "ON");

    // Built-in commands (default ON)
    dhsh_config_add_bool("builtin_cd", 1, "ON");
    dhsh_config_add_bool("builtin_export", 1, "ON");
    dhsh_config_add_bool("builtin_unset", 1, "ON");
    dhsh_config_add_bool("builtin_history", 1, "ON");
    dhsh_config_add_bool("builtin_echo", 1, "ON");
    dhsh_config_add_bool("builtin_pwd", 1, "ON");
    dhsh_config_add_bool("builtin_env", 1, "ON");
    dhsh_config_add_bool("builtin_clear", 1, "ON");
    dhsh_config_add_bool("builtin_date", 1, "ON");
    dhsh_config_add_bool("builtin_whoami", 1, "ON");
    dhsh_config_add_bool("builtin_aliases", 1, "ON");
    dhsh_config_add_bool("builtin_whitelist", 1, "ON");

    // Whitelist (default OFF - allows all commands)
    dhsh_config_add_bool("command_whitelist", 0, "OFF");
    dhsh_config_add_string("whitelist_file", "/etc/dhsh_whitelist", "/etc/dhsh_whitelist");

    // Seccomp (default OFF)
    dhsh_config_add_bool("seccomp_filter", 0, "OFF");

    // Path protection
    dhsh_config_add_bool("path_traversal_protection", 1, "ON");
    dhsh_config_add_int("max_path_length", 4096, "4096");

    // Expansions (all default OFF for security)
    dhsh_config_add_bool("expansion_variable", 0, "OFF");
    dhsh_config_add_bool("expansion_command", 0, "OFF");
    dhsh_config_add_bool("expansion_arithmetic", 0, "OFF");
    dhsh_config_add_bool("expansion_globbing", 0, "OFF");
    dhsh_config_add_bool("expansion_brace", 0, "OFF");
    dhsh_config_add_bool("expansion_tilde", 0, "OFF");

    // Heredoc (default OFF)
    dhsh_config_add_bool("heredoc", 0, "OFF");

    // Aliases
    dhsh_config_add_bool("aliases", 1, "ON");
    dhsh_config_add_int("max_aliases", 32, "32");

    // Prompt
    dhsh_config_add_string("prompt_format", "%u@%h %w$", "%u@%h %w$");

    // Logging
    dhsh_config_add_bool("log_commands", 0, "OFF");
    dhsh_config_add_string("log_file", "/var/log/dhsh.log", "/var/log/dhsh.log");

    // EOF handling
    dhsh_config_add_bool("exit_on_eof", 1, "ON");
    dhsh_config_add_bool("exit_message", 1, "ON");

    // Build default values lookup (simplified approach)
    for (int i = 0; i < g_config_count; i++) {
        g_default_values[i] = g_config_entries[i].default_value;
    }
    g_default_count = g_config_count;

    // Determine config file path
    char config_file[512];
    if (!config_path) {
        // Try user's home directory
        const char *home = getenv("HOME");
        if (home) {
            snprintf(config_file, sizeof(config_file), "%s/.dhshrc", home);
            config_path = config_file;
        } else {
            return 0;  // No config file to load
        }
    }

    // Try to open and parse config file
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        // Config file not found - that's okay, use defaults
        return 0;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        // Skip empty lines and comments
        char *trimmed = trim_whitespace(line);
        if (*trimmed == '\0' || *trimmed == '#') {
            continue;
        }

        // Parse key = value
        char *eq = strchr(trimmed, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = trim_whitespace(trimmed);
        char *value = trim_whitespace(eq + 1);

        // Skip if key is empty
        if (*key == '\0') continue;

        // Look up and set the configuration
        config_entry_t *entry = dhsh_config_find(key);
        if (entry) {
            switch (entry->type) {
                case DHSH_CONFIG_STRING:
                    dhsh_config_set_string(key, value);
                    break;
                case DHSH_CONFIG_INT: {
                    int int_val = atoi(value);
                    dhsh_config_set_int(key, int_val);
                    break;
                }
                case DHSH_CONFIG_BOOL:
                    dhsh_config_set_bool(key, parse_bool(value));
                    break;
            }
        }
    }

    fclose(fp);
    return 0;
}

// Get a string config value
const char *dhsh_get_config_string(const char *name) {
    config_entry_t *entry = dhsh_config_find(name);
    if (entry && entry->type == DHSH_CONFIG_STRING) {
        return entry->value.str_val;
    }
    return NULL;
}

// Get an integer config value
int dhsh_get_config_int(const char *name, int default_value) {
    config_entry_t *entry = dhsh_config_find(name);
    if (entry && entry->type == DHSH_CONFIG_INT) {
        return entry->value.int_val;
    }
    return default_value;
}

// Get a boolean config value
int dhsh_get_config_bool(const char *name, int default_value) {
    config_entry_t *entry = dhsh_config_find(name);
    if (entry && entry->type == DHSH_CONFIG_BOOL) {
        return entry->value.bool_val;
    }
    return default_value;
}

// Built-in command: display or set configuration
int dhsh_config(char **args) {
    if (args[1] == NULL) {
        // Display all configuration
        printf("dhsh Configuration\n");
        printf("==================\n\n");
        for (int i = 0; i < g_config_count; i++) {
            config_entry_t *entry = &g_config_entries[i];
            printf("%s = ", entry->name);
            switch (entry->type) {
                case DHSH_CONFIG_STRING:
                    printf("%s (default: %s)\n", entry->value.str_val, entry->default_value);
                    break;
                case DHSH_CONFIG_INT:
                    printf("%d (default: %s)\n", entry->value.int_val, entry->default_value);
                    break;
                case DHSH_CONFIG_BOOL:
                    printf("%s (default: %s)\n",
                           entry->value.bool_val ? "ON" : "OFF",
                           entry->default_value);
                    break;
            }
        }
    } else if (args[1] && args[2] && strcmp(args[1], "set") == 0) {
        // Set a configuration value: config set key value
        if (args[3] == NULL) {
            fprintf(stderr, "dhsh: config: missing value\n");
            return 1;
        }
        config_entry_t *entry = dhsh_config_find(args[2]);
        if (!entry) {
            fprintf(stderr, "dhsh: config: unknown setting '%s'\n", args[2]);
            return 1;
        }

        if (entry->type == DHSH_CONFIG_STRING) {
            dhsh_config_set_string(args[2], args[3]);
        } else if (entry->type == DHSH_CONFIG_INT) {
            dhsh_config_set_int(args[2], atoi(args[3]));
        } else if (entry->type == DHSH_CONFIG_BOOL) {
            dhsh_config_set_bool(args[2], parse_bool(args[3]));
        }
        printf("Set %s to %s\n", args[2], args[3]);
    } else if (args[1] && strcmp(args[1], "reset") == 0) {
        // Reset all configuration to defaults
        fprintf(stderr, "dhsh: config reset not implemented\n");
    } else {
        fprintf(stderr, "Usage: config [set <key> <value>|reset]\n");
    }
    return 1;
}
