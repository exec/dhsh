# dhsh - The Dumb Hard Shell

A modern, feature-rich Linux shell with security by default and configurable paranoia.

## Features

### Core Functionality
- **Process execution**: Launch any program in your PATH
- **Piping**: Chain commands with `|`
- **I/O redirection**: Support for `>`, `>>`, `<`, `2>`, `&>`
- **Command history**: Navigate with up/down arrows
- **Line editing**: Full terminal control with backspace, Ctrl+U
- **Built-in commands**: `cd`, `help`, `exit`, `export`, `unset`, `history`, `echo`, `config`

### Security Features

#### Security by Default (Configurable)
- **Input validation**: Command length limits (4096 chars), argument count limits (256 args)
- **Environment protection**: Blocks modification of critical variables (`LD_PRELOAD`, `PATH`, `IFS`, etc.)
- **Path traversal protection**: Prevents `../` directory traversal attacks
- **Security-by-default**: Expansion features disabled to prevent injection attacks

#### High-Paranoid Mode
- **Seccomp filters**: Restrict child processes to safe syscalls
- **Command whitelist**: Allow only specific commands
- **No shell expansions**: Variable, command, glob, arithmetic expansion disabled

### Configuration

dhsh reads `~/.dhshrc` on startup for customizable settings:

```bash
# View current configuration
config

# Set a configuration value
config set history_size 200
config set expansion_variable ON
config set command_whitelist ON

# Use a custom config file
./build/dhsh -c /path/to/custom.rc
```

See `.dhshrc` for all available settings (38+ configurable options).

## Building

```bash
make                    # Build dhsh
sudo make install       # Install to /usr/local/bin
make clean             # Clean build artifacts
```

## Usage

```bash
./build/dhsh           # Run from build directory
dhsh                   # Run if installed system-wide
```

### Examples

```bash
# Basic commands
ls -la
pwd
cd /tmp

# Piping
ls | grep ".txt"
ps aux | grep dhsh | wc -l

# I/O Redirection
echo "Hello" > output.txt
cat < input.txt
ls >> files.txt
command 2> errors.txt
command &> all_output.txt

# Environment variables
export MY_VAR=value
unset MY_VAR

# Command history
history              # Show command history
↑/↓                 # Navigate history

# Configuration
config               # View all settings
config set seccomp_filter ON  # Enable paranoid mode
```

## Configuration Modes

### Default (Balanced) Mode
Full-featured shell with baseline security:
- All built-ins enabled
- Expansions disabled (secure by default)
- Input validation enabled
- Environment protection enabled
- Seccomp disabled (for compatibility)

### Paranoid Mode (Maximum Security)
Enable in `.dhshrc`:
```bash
# Maximum security - disable dangerous features
expansion_variable = OFF
expansion_command = OFF
expansion_globbing = OFF
seccomp_filter = ON
command_whitelist = ON
```

### Convenience Mode (Maximum Features)
Enable in `.dhshrc`:
```bash
# Full features - enable all expansions
expansion_variable = ON
expansion_command = ON
expansion_globbing = ON
seccomp_filter = OFF
command_whitelist = OFF
```

## Security Philosophy

dhsh follows "security by configuration":

1. **Secure by default**: Dangerous features (expansions) are disabled
2. **Configurable paranoia**: Enable higher security via `.dhshrc`
3. **No shell scripting**: Eliminates entire classes of injection vulnerabilities by default
4. **Minimal attack surface**: Small codebase that's easy to audit
5. **Explicit trade-offs**: You decide between convenience and security

## Limitations

**By default, dhsh does NOT support:**
- Variable expansion (`$VAR`, `${VAR}`) - disable `expansion_variable` to enable
- Command substitution (`$(cmd)` or `` `cmd` ``) - disable `expansion_command` to enable
- Arithmetic operations (`$((2+2))`) - disable `expansion_arithmetic` to enable
- Pathname globbing (`*.txt`) - disable `expansion_globbing` to enable
- Brace expansion (`{a,b}`) - disable `expansion_brace` to enable
- Job control (background processes with `&`)
- Heredocs - disable `heredoc` to enable

**Note**: Expansion features are disabled by default for security. Enable them in `.dhshrc` only if needed.

## Use Cases

dhsh is ideal for:
- **Restricted user accounts** with configurable access levels
- **Container entrypoints** with minimal attack surface
- **High-security environments** where Paranoid Mode is enabled
- **Systems where shell exploits must be prevented**
- **Embedded systems** with limited resources
- **Multi-user systems** where users need shell access but shouldn't break things

## Testing

```bash
./scripts/fuzz.sh              # Run fuzzing tests for security
gcc -Iinclude -o test test_security.c src/dhsh_security.c && ./test  # Security unit tests
```

## License

MIT License - see LICENSE file

## Contributing

Security is paramount. Any contributions must:
1. Maintain or improve security posture
2. Not increase complexity unnecessarily
3. Include tests for new functionality
4. Follow existing code style
5. Document security implications of changes
