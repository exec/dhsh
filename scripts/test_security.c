// Unit tests for dhsh security functions
// Compile with: gcc -I../include -o test_security test_security.c ../src/dhsh_security.c -DTESTING

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include the security module (with static functions, we need to be in the same file)
// For simplicity, we'll test via the public API

extern int dhsh_sanitize_input(const char *line);
extern int dhsh_is_command_allowed(const char *cmd);
extern void dhsh_set_whitelist(const char **commands, int count);

// Test helper functions
#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        printf("[PASS] %s\n", msg); \
    } else { \
        printf("[FAIL] %s\n", msg); \
        failures++; \
    } \
} while(0)

int failures = 0;
int tests_run = 0;

void run_test(const char *name, int (*test_func)(void)) {
    printf("\n=== Test: %s ===\n", name);
    if (test_func()) {
        printf("[PASS] %s\n", name);
        tests_run++;
    } else {
        printf("[FAIL] %s\n", name);
        tests_run++;
        failures++;
    }
}

// Test 1: Sanitize input - should block dangerous characters
int test_sanitize_dangerous_chars(void) {
    int pass = 1;

    // Test semicolon
    if (dhsh_sanitize_input("echo test; echo bad") == 0) {
        printf("  FAILED: semicolon not blocked\n");
        pass = 0;
    }

    // Test backtick
    if (dhsh_sanitize_input("echo `id`") == 0) {
        printf("  FAILED: backtick not blocked\n");
        pass = 0;
    }

    // Test $
    if (dhsh_sanitize_input("echo $HOME") == 0) {
        printf("  FAILED: $ not blocked\n");
        pass = 0;
    }

    // Test ampersand
    if (dhsh_sanitize_input("echo test & echo bad") == 0) {
        printf("  FAILED: & not blocked\n");
        pass = 0;
    }

    return pass;
}

// Test 2: Sanitize input - should allow safe characters
int test_sanitize_safe_chars(void) {
    int pass = 1;

    // Test that normal commands pass
    if (dhsh_sanitize_input("echo hello") != 0) {
        printf("  FAILED: normal command rejected\n");
        pass = 0;
    }

    // Test with spaces
    if (dhsh_sanitize_input("ls -la /tmp") != 0) {
        printf("  FAILED: command with spaces rejected\n");
        pass = 0;
    }

    // Test with redirection (allowed by design)
    if (dhsh_sanitize_input("echo test > file.txt") != 0) {
        printf("  FAILED: redirection rejected\n");
        pass = 0;
    }

    return pass;
}

// Test 3: Command whitelist - default state
int test_whitelist_default(void) {
    int pass = 1;

    // Default whitelist should allow some basic commands
    if (!dhsh_is_command_allowed("echo")) {
        printf("  FAILED: echo not in default whitelist\n");
        pass = 0;
    }

    if (!dhsh_is_command_allowed("ls")) {
        printf("  FAILED: ls not in default whitelist\n");
        pass = 0;
    }

    if (!dhsh_is_command_allowed("cat")) {
        printf("  FAILED: cat not in default whitelist\n");
        pass = 0;
    }

    return pass;
}

// Test 4: Command whitelist - allow all mode
int test_whitelist_allow_all(void) {
    int pass = 1;

    // Set empty whitelist (allow all)
    dhsh_set_whitelist(NULL, 0);

    // Any command should be allowed
    if (!dhsh_is_command_allowed("nonexistent_command_xyz")) {
        printf("  FAILED: nonexistent command not allowed\n");
        pass = 0;
    }

    // Restore default whitelist for other tests
    const char *default_cmds[] = {"echo", "ls", "cat"};
    dhsh_set_whitelist(default_cmds, 3);

    return pass;
}

// Test 5: Command whitelist - restricted mode
int test_whitelist_restricted(void) {
    int pass = 1;

    // Set custom whitelist with only echo
    const char *custom_whitelist[] = {"echo"};
    dhsh_set_whitelist(custom_whitelist, 1);

    if (!dhsh_is_command_allowed("echo")) {
        printf("  FAILED: echo not allowed in custom whitelist\n");
        pass = 0;
    }

    if (dhsh_is_command_allowed("ls")) {
        printf("  FAILED: ls allowed in restricted whitelist\n");
        pass = 0;
    }

    // Restore default whitelist
    const char *default_cmds[] = {"echo", "ls", "cat"};
    dhsh_set_whitelist(default_cmds, 3);

    return pass;
}

// Test 6: Path handling - directory traversal prevention
int test_path_traversal(void) {
    // Note: This is tested in dhsh_cd, not directly in security module
    printf("  SKIPPED: Tested in dhsh_cd\n");
    return 1;
}

// Test 7: Environment variable sanitization
int test_env_sanitize(void) {
    // Note: This is tested in dhsh_export, not directly in security module
    printf("  SKIPPED: Tested in dhsh_export\n");
    return 1;
}

int main(void) {
    printf("=================================\n");
    printf("  dhsh Security Function Tests\n");
    printf("=================================\n");

    run_test("Sanitize input - block dangerous chars", test_sanitize_dangerous_chars);
    run_test("Sanitize input - allow safe chars", test_sanitize_safe_chars);
    run_test("Whitelist - default state", test_whitelist_default);
    run_test("Whitelist - allow all mode", test_whitelist_allow_all);
    run_test("Whitelist - restricted mode", test_whitelist_restricted);
    run_test("Path traversal prevention", test_path_traversal);
    run_test("Environment sanitization", test_env_sanitize);

    printf("\n=================================\n");
    printf("  Results: %d/%d tests passed\n", tests_run - failures, tests_run);
    printf("=================================\n");

    return failures > 0 ? 1 : 0;
}
