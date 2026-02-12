#ifndef DHSH_SECURITY_H
#define DHSH_SECURITY_H

#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>

// Maximum allowed command length
#define DHSH_MAX_CMD_LEN 4096

// Maximum allowed argument count
#define DHSH_MAX_ARGS 256

// Maximum allowed environment variable size
#define DHSH_MAX_ENV_SIZE 32768

// Maximum number of whitelisted commands
#define DHSH_MAX_WHITELIST 128

// Function to validate command arguments
int dhsh_validate_args(char **args);

// Function to sanitize environment variables
int dhsh_sanitize_env(const char *name, const char *value);

// Function to apply seccomp filters to child processes
void dhsh_apply_child_seccomp(void);

// Function to check if a command is in the allowed list
int dhsh_is_command_allowed(const char *cmd);

/**
 * @brief Set the whitelist of allowed commands.
 * @param commands Array of command names.
 * @param count Number of commands in the array.
 */
void dhsh_set_whitelist(const char **commands, int count);

/**
 * @brief Sanitize command line input to prevent injection attacks.
 * @param line The command line to sanitize.
 * @return 0 if valid, -1 if dangerous characters are found.
 */
int dhsh_sanitize_input(const char *line);

// Global whitelist variables (extern)
extern const char *g_dhsh_whitelist[DHSH_MAX_WHITELIST];
extern int g_dhsh_whitelist_count;

#endif // DHSH_SECURITY_H