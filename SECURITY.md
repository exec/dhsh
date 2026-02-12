# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Features

dhsh implements several security measures to minimize attack surface:

### Hardened Compilation
- **FORTIFY_SOURCE Level 3**: Enables additional buffer overflow checks
- **Stack Protector Strong**: Protects against stack-based buffer overflows
- **Position Independent Executable (PIE/ASLR)**: Enables address space randomization
- **Full RELRO**: Relocation Read-Only protects GOT from overwrites
- **NOW binding**: Immediate symbol resolution prevents GOTPLT attacks

### Input Validation
- Command length limited to 4096 characters
- Argument count limited to 256 arguments
- Environment variable size limited to 32768 bytes
- Dangerous characters blocked: `;`, `` ` ``, `|`, `&`, `$`

### Process Isolation
- **Seccomp filters** (enabled by default): Restricts child processes to safe syscalls
- **Environment sanitization**: Blocks modification of `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH`, and other critical variables
- **Path resolution**: Uses `realpath()` to prevent directory traversal

### Command Whitelist
- Optional whitelist of allowed commands (54 commands by default)
- Whitelist can be managed via `whitelist` built-in command
- Supports adding, removing, and resetting the whitelist

## Security Philosophy

dhsh follows the principle of "security through simplicity":

1. **No shell scripting**: Eliminates entire classes of injection vulnerabilities
2. **No expansions**: No variable, arithmetic, command, or pathname expansion
3. **No globbing**: Treats `*` and `?` literally
4. **Minimal attack surface**: Small codebase that's easy to audit
5. **Secure by default**: Restrictive permissions and validations

## Known Limitations

- No job control (background processes)
- No shell functions or aliases as true shell features
- No heredoc support (planned)
- No line continuation support

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **Do not** create a public GitHub issue
2. Email maintainers directly with details
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- Acknowledgment: Within 48 hours
- Status update: Within 7 days
- Resolution: As soon as possible

## Security Best Practices for Users

1. **Use the whitelist**: Restrict commands to only what's needed
2. **Keep dhsh updated**: Security fixes are released regularly
3. **Audit command history**: Review `history` for unexpected commands
4. **Use in restricted environments**: Ideal for containers, chroot jails

## Security Audit Checklist

When auditing dhsh code, verify:
- [ ] No buffer overflows in input parsing
- [ ] No command injection in command execution
- [ ] No environment variable poisoning
- [ ] Seccomp filters are properly configured
- [ ] File descriptors are properly closed
- [ ] Memory is properly freed
- [ ] Signal handlers are async-signal-safe
