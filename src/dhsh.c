#include "dhsh.h"
#include "dhsh_security.h"
#include <fcntl.h>
#include <termios.h> // For terminal control
#include <limits.h> // For PATH_MAX

// Global history buffer
char *g_dhsh_history_commands[DHSH_HISTORY_SIZE];
int g_dhsh_history_count = 0;

// Global termios structures to save and restore terminal settings
static struct termios g_original_termios;
static struct termios g_raw_termios;

// Function to restore original terminal settings
void dhsh_restore_termios(void) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_original_termios);
}

// Signal handler for SIGINT (Ctrl+C)
void dhsh_sigint_handler(int signo __attribute__((unused))) {
    // Print ^C to show the interrupt, just like bash
    printf("^C\n");
    fflush(stdout);
    
    // No need to change terminal modes for this simple output
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
    "info"
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
    &dhsh_info
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
    for (int i = 0; i < g_dhsh_history_count; i++) {
        printf("%d: %s\n", i, g_dhsh_history_commands[i]);
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

        // Optional: Apply seccomp filters for additional security
        // Note: This might break some programs that need syscalls not in our whitelist
        // Uncomment the line below to enable:
        // dhsh_apply_child_seccomp();

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

// Parses redirection operators and their files from the arguments.
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

// Execute shell built-in or launch program
int dhsh_execute(char **args) {
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

    // Check if the command is a built-in
    for (int i = 0; i < dhsh_num_builtins(); i++) {
        if (strcmp(args[0], builtin_str[i]) == 0) {
            return (*builtin_func[i])(args);
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
            // Store command in history
            if (g_dhsh_history_count < DHSH_HISTORY_SIZE) {
                g_dhsh_history_commands[g_dhsh_history_count] = strdup(line);
                g_dhsh_history_count++;
            } else {
                free(g_dhsh_history_commands[0]); // Free oldest command
                for (int i = 0; i < DHSH_HISTORY_SIZE - 1; i++) {
                    g_dhsh_history_commands[i] = g_dhsh_history_commands[i+1];
                }
                g_dhsh_history_commands[DHSH_HISTORY_SIZE - 1] = strdup(line);
            }

            args = dhsh_split_line(line);
            status = dhsh_execute(args);
            free(line);
            free(args);
        }
    } while (status);
}

// --- Main Entry Point ---

// Cleanup function to free all history
void dhsh_cleanup_history(void) {
    for (int i = 0; i < g_dhsh_history_count; i++) {
        free(g_dhsh_history_commands[i]);
        g_dhsh_history_commands[i] = NULL;
    }
    g_dhsh_history_count = 0;
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
            printf("\nBuilt-in commands:\n");
            printf("  cd, help, exit, export, unset, history, echo, version, info\n");
            return EXIT_SUCCESS;
        } else if (strcmp(argv[1], "-c") == 0 && argc > 2) {
            // Execute a single command and exit (like bash -c)
            // This is useful for scripts but maintains security
            printf("dhsh: -c option not implemented for security reasons\n");
            return EXIT_FAILURE;
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

    // In a real shell, one would load config files here.
    // dhsh has no config files for simplicity and security.

    // Run the command loop.
    dhsh_loop();

    // Perform any shutdown/cleanup.
    return EXIT_SUCCESS;
}
