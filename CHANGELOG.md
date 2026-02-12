# Changelog

All notable changes to dhsh will be documented in this file.

## [Unreleased] - Planned

### Added
- **Configuration System**
  - `.dhshrc` config file for customizable shell behavior
  - `config` built-in command to view and set configuration
  - Command-line option `-c <config>` to use custom config file
  - 38+ configurable settings for security features and behaviors
  - Config file supports ON/OFF booleans, integers, and strings

- **Security Features**
  - Enabled seccomp filters by default (previously disabled)
  - Implemented functional command whitelist (54 commands default)
  - Added `whitelist` built-in for whitelist management
  - Fixed signal handler async-safety (using `write()` instead of `printf()`)

- **Built-in Commands**
  - `pwd` - Display current working directory
  - `env` - Display environment variables
  - `clear` - Clear terminal screen
  - `date` - Display current date/time
  - `whoami` - Display current username
  - `aliases` / `alias` - Display and set command aliases
  - `jobs` - Display background jobs (placeholder)
  - `whitelist` - Manage whitelist of allowed commands
  - `config` - Display and modify shell configuration

- **Redirection Support**
  - Fixed redirection for built-in commands (previously only worked for external commands)
  - 2> stderr redirection support (was already implemented)

- **Input Validation**
  - Enhanced input sanitization blocking dangerous characters
  - Added heredoc-aware token splitting for `<<` operator

- **Documentation**
  - Added SECURITY.md with detailed security policy
  - Added LICENSE (MIT)
  - Added CHANGELOG.md
  - Added `.dhshrc` example configuration file

- **Testing**
  - Improved fuzzing script with 41 comprehensive test cases
  - Added unit tests for security functions
  - Fixed test script logic

### Changed
- Default whitelist now allows common Unix commands
- Command whitelist can be set to "allow all" mode
- History now properly manages memory
- Default config enables security features by default

### Fixed
- Memory leaks in history buffer management
- Function name mismatch (`dhsh_builtin_history` vs `dhsh_history`)
- Portability issues (added missing includes for time.h, ctype.h, pwd.h)
- Warning: ignoring return value of write() in signal handler
- History circular buffer logic (proper handling of full buffer state)

### Removed
- Removed static declaration conflict for whitelist variables

### Known Limitations (By Design)
- No shell scripting (if, for, while, functions)
- No variable expansion ($VAR, ${VAR}) - configurable via `expansion_variable` setting
- No command substitution ($(cmd), backticks) - configurable via `expansion_command` setting
- No arithmetic operations - configurable via `expansion_arithmetic` setting
- No pathname globbing (*.txt) - configurable via `expansion_globbing` setting
- No job control (background processes)
- No heredoc support - configurable via `heredoc` setting

### Notes
This is the initial release with a flexible configuration system. The shell can now be customized
via `.dhshrc` to enable/disable various security features and shell behaviors. The default
configuration is set to a full-featured shell with security features enabled.
