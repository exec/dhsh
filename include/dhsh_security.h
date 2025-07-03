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

// Function to validate command arguments
int dhsh_validate_args(char **args);

// Function to sanitize environment variables
int dhsh_sanitize_env(const char *name, const char *value);

// Function to apply seccomp filters to child processes
void dhsh_apply_child_seccomp(void);

// Function to check if a command is in the allowed list
int dhsh_is_command_allowed(const char *cmd);

#endif // DHSH_SECURITY_H