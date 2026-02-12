# dhsh - The Dumb Hard Shell

A minimalist, security-focused Linux shell that prioritizes safety over features.

## Features

### Core Functionality
- **Process execution**: Launch any program in your PATH
- **Piping**: Chain commands with `|`
- **I/O redirection**: Support for `>`, `>>`, `<`, `2>`, `&>`
- **Command history**: Navigate with up/down arrows
- **Line editing**: Full terminal control with backspace, Ctrl+U
- **Built-in commands**: `cd`, `help`, `exit`, `export`, `unset`, `history`, `echo`

### Security Features
- **Hardened compilation**: Built with `-D_FORTIFY_SOURCE=3`, stack protector, PIE/ASLR
- **Input validation**:
  - Command length limits (4096 chars)
  - Argument count limits (256 args)
  - Path length validation
- **Protected environment variables**: Blocks modification of `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH`, etc.
- **Memory safety**: Proper cleanup on exit, no memory leaks
- **Path resolution**: Uses `realpath()` to prevent directory traversal
- **Optional seccomp filters**: Can restrict syscalls for child processes

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
```

## Security Philosophy

dhsh follows the principle of "security through simplicity":

1. **No shell scripting**: Eliminates entire classes of injection vulnerabilities
2. **No expansions**: No variable, arithmetic, command, or pathname expansion
3. **No globbing**: Treats `*` and `?` literally
4. **Minimal attack surface**: Small codebase that's easy to audit
5. **Secure by default**: Restrictive permissions and validations

## Limitations

By default, dhsh is configured with security features enabled. These can be customized in `~/.dhshrc`:

**Security-by-default (configurable):**
- No shell scripting (if, for, while, functions)
- No variable expansion (`$VAR`, `${VAR}`) - disable `expansion_variable` to enable
- No command substitution (`$(cmd)` or `` `cmd` ``) - disable `expansion_command` to enable
- No arithmetic operations (`$((2+2))`) - disable `expansion_arithmetic` to enable
- No pathname globbing (`*.txt`) - disable `expansion_globbing` to enable
- No job control (background processes with `&`)

**Note**: Expansion features are disabled by default for security. Enable them in `.dhshrc` only if needed.

## Use Cases

dhsh is ideal for:
- Restricted user accounts
- Container entrypoints
- High-security environments
- Systems where shell exploits must be prevented
- Embedded systems with limited resources

## Testing

```bash
./test.sh              # Run basic functionality tests
./fuzz.sh              # Run fuzzing tests for security
```

## License

[Add your license here]

## Contributing

Security is paramount. Any contributions must:
1. Maintain or improve security posture
2. Not increase complexity unnecessarily
3. Include tests for new functionality
4. Follow existing code style
