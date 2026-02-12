#ifndef DHSH_H
#define DHSH_H

// Standard Library Headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// POSIX/Linux Headers
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>



// --- Constants ---

// Version information
#define DHSH_VERSION "1.0.0"
#define DHSH_VERSION_STRING "dhsh version " DHSH_VERSION
#define DHSH_BUILD_DATE __DATE__
#define DHSH_BUILD_TIME __TIME__

// Buffer sizes for dynamic allocation
#define DHSH_RL_BUFSIZE 1024
#define DHSH_TOK_BUFSIZE 64

// History buffer size
#define DHSH_HISTORY_SIZE 100

// Global history buffer
extern char *g_dhsh_history_commands[DHSH_HISTORY_SIZE];
extern int g_dhsh_history_count;

// Circular buffer indices
extern int g_dhsh_history_head;  // Index of newest entry
extern int g_dhsh_history_tail;  // Index of oldest entry
extern int g_dhsh_history_full;  // Flag: buffer is full

// Delimiters for command line parsing
#define DHSH_TOK_DELIM " \t\r\n\a"

// ANSI color codes for the prompt
#define DHSH_COLOR_WHITE "\x1b[97m"
#define DHSH_COLOR_CYAN  "\x1b[96m"
#define DHSH_COLOR_RESET "\x1b[0m"

// ANSI escape codes for cursor movement and screen manipulation
#define DHSH_ESC_SEQ_START '\x1b'
#define DHSH_ARROW_UP    "[A"
#define DHSH_ARROW_DOWN  "[B"
#define DHSH_ARROW_RIGHT "[C"
#define DHSH_ARROW_LEFT  "[D"
#define DHSH_CLEAR_LINE  "\x1b[2K\r" // Clear line and return cursor to beginning



// --- Function Prototypes ---

/**
 * @brief Main loop of the shell.
 */
void dhsh_loop(void);

/**
 * @brief Read a line of input from stdin.
 * @return The line read from stdin as a dynamically allocated string.
 */
char *dhsh_read_line(void);

/**
 * @brief Split a line into tokens (arguments).
 * @param line The line to split.
 * @return A NULL-terminated array of tokens.
 */
char **dhsh_split_line(char *line);

/**
 * @brief Split a line into commands (separated by '|').
 * @param line The line to split.
 * @return A NULL-terminated array of commands.
 */
char **dhsh_split_line_pipe(char *line);

/**
 * @brief Parses redirection operators and their files from the arguments.
 * @param args Null-terminated list of arguments.
 * @return 0 on success, -1 on error.
 */
int dhsh_parse_redirections(char ***args_ptr);

/**
 * @brief Execute a command.
 * @param args Null-terminated list of arguments (including command).
 * @param original_line The original command line for sanitization.
 * @return 1 to continue the loop, 0 to exit.
 */
int dhsh_execute(char **args, const char *original_line);

/**
 * @brief Built-in command: display history.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_history(char **args);

/**
 * @brief Get the number of built-in commands.
 * @return The number of built-in commands.
 */
int dhsh_num_builtins(void);

/**
 * @brief Built-in command: display current directory.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_pwd(char **args);

/**
 * @brief Built-in command: display environment variables.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_env(char **args);

/**
 * @brief Built-in command: clear terminal screen.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_clear(char **args);

/**
 * @brief Built-in command: display current date/time.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_date(char **args);

/**
 * @brief Built-in command: display current user.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_whoami(char **args);

/**
 * @brief Built-in command: display set aliases.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_aliases(char **args);

/**
 * @brief Built-in command: display background jobs.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_jobs(char **args);

/**
 * @brief Built-in command: display set aliases.
 * @param args Command arguments (alias definition).
 * @return 1 to continue the loop.
 */
int dhsh_set_alias(char **args);

/**
 * @brief Built-in command: display config settings.
 * @param args Command arguments (unused).
 * @return 1 to continue the loop.
 */
int dhsh_config(char **args);

/**
 * @brief Initialize shell configuration from config file.
 * @param config_path Path to configuration file.
 * @return 0 on success, -1 on error.
 */
int dhsh_init_config(const char *config_path);

/**
 * @brief Get a string config value.
 * @param name Configuration key name.
 * @return Configuration value, or NULL if not found.
 */
const char *dhsh_get_config_string(const char *name);

/**
 * @brief Get an integer config value.
 * @param name Configuration key name.
 * @param default_value Value to return if key not found.
 * @return Configuration value or default.
 */
int dhsh_get_config_int(const char *name, int default_value);

/**
 * @brief Get a boolean config value.
 * @param name Configuration key name.
 * @param default_value Value to return if key not found.
 * @return Configuration value or default (1=ON, 0=OFF).
 */
int dhsh_get_config_bool(const char *name, int default_value);

#endif // DHSH_H
