# SymFit MCP Server Changelog

## Version 1.0.4 (2025-10-13)

### Changed
- **Timeout Configuration**: Improved timeout handling with separate per-execution and total campaign timeouts
  - `timeout` (per-execution): Reduced default from 30000ms to **500ms**
    - Each individual symbolic execution run is limited to 500ms
    - This prevents any single execution from taking too long
  - `campaign_timeout` (total): New parameter, default **300000ms (5 minutes)**
    - Maximum time for the entire multi-round campaign
    - Campaign stops when total time exceeds this limit
  - Campaign results now include `elapsed_time_ms` and `elapsed_time_seconds`

### Rationale
- Symbolic execution should be fast per input (500ms is usually sufficient)
- Total campaign time should be controllable to prevent indefinite runs
- Separate timeouts allow fine-grained control over execution vs campaign duration

### Impact
- **Breaking change for long-running individual executions**: Default per-execution timeout reduced from 30s to 500ms
  - Override with `timeout` parameter if needed: `{timeout: 30000}`
- Campaigns now terminate gracefully on total timeout with `stop_reason: "campaign_timeout"`
- Better resource control and predictable execution times

## Version 1.0.3 (2025-10-13)

### Added
- **Stdin Input Support**: Added `use_stdin` parameter to `run_symbolic_execution` and `run_campaign` tools
  - Default value: `false` (backward compatible - uses file input)
  - When `true`, pipes input to binary's stdin instead of using a file
  - Useful for analyzing programs that read from stdin (filters, parsers, CLI tools, etc.)
  - Input data is still written to a file for SymFit to track, then piped to stdin during execution

### Technical Details
- Docker runs with `-i` flag in stdin mode for interactive stdin handling
- Uses shell wrapper: `cat input_file | fgtest symqemu binary`
- Input file path still required for SymFit taint tracking (`TAINT_OPTIONS=taint_file=...`)
- `input_filename` parameter ignored when `use_stdin` is true

### Impact
- Enables analysis of stdin-reading programs (previously only file-reading programs supported)
- Common use cases: command-line tools, filters, parsers, network protocol handlers
- No breaking changes - default behavior remains file-based input

### Testing
- Added `test-stdin.sh` script to verify stdin mode functionality
- Created `STDIN-USAGE.md` with comprehensive usage guide and examples

## Version 1.0.2 (2025-10-13)

### Added
- **Custom Input Filename Support**: Added `input_filename` parameter to `run_symbolic_execution` and `run_campaign` tools
  - Default value: `"testfile"` (backward compatible with existing usage)
  - Allows analyzing binaries that read from different file names (e.g., `config.txt`, `input.dat`, etc.)
  - Previously hardcoded to `"testfile"`, only working for the specific test program included

### Impact
- Can now analyze real-world binaries with custom input file expectations
- No breaking changes - default behavior unchanged for existing users
- Enables broader applicability of the MCP server

## Version 1.0.1 (2025-10-13)

### Fixed
- **Docker Permission Issue**: Added `--user` flag to Docker execution to ensure files created inside containers have correct ownership
  - Files are now created with the current user's UID:GID instead of root:root
  - Multi-round campaigns now work properly as the MCP server can read generated test cases
  - This fix enables proper corpus growth across multiple rounds

### Technical Details
- Added `process.getuid()` and `process.getgid()` calls to determine current user
- Docker containers now run with `--user ${uid}:${gid}` flag
- Fallback to UID/GID 1000 if process methods unavailable (e.g., Windows)

### Impact
- Before fix: Round 1 only (0 new cases in subsequent rounds due to permission errors)
- After fix: Full multi-round campaigns work (79 cases generated across 3 rounds in testing)

## Version 1.0.0 (2025-10-13)

### Added
- Initial release of SymFit MCP Server
- 6 tools for symbolic execution:
  - `run_symbolic_execution` - Single execution with specific input
  - `initialize_corpus` - Create corpus with seed inputs
  - `add_to_corpus` - Add test cases with deduplication
  - `run_campaign` - Iterative multi-round symbolic execution
  - `analyze_corpus` - Get corpus statistics
  - `read_test_case` - Read specific test case details

### Features
- Docker-based execution (default mode)
- Native execution support (optional)
- Automatic corpus management and deduplication
- Multi-round campaign support
- SHA1-based test case hashing
- Base64 encoding for binary data
- Comprehensive error handling
- Timeout configuration per execution

### Documentation
- Complete README with all tool specifications
- Quick start guide
- VS Code / Claude Code setup instructions
- Docker setup guide
- 10 detailed usage examples
- Troubleshooting guides

### Configuration
- Project-level `.mcp.json` for VS Code integration
- Environment variables for customization:
  - `SYMFIT_USE_DOCKER` - Enable/disable Docker mode
  - `SYMFIT_DOCKER_IMAGE` - Docker image to use
  - `SYMFIT_BUILD_DIR` - Build directory (native mode)
  - `SYMFIT_WORK_DIR` - Working directory

### Testing
- Automated test scripts for Docker and MCP functionality
- Example test binary included
- Campaign simulation script

## Future Enhancements

### Planned
- Progress callbacks during long campaigns
- Parallel execution of multiple inputs
- Coverage metrics integration
- Support for custom constraint solvers
- Web dashboard for campaign monitoring
- Integration with CI/CD pipelines
- Support for other symbolic execution backends

### Under Consideration
- Streaming campaign results
- Checkpoint/resume functionality
- Distributed execution across multiple containers
- Machine learning-guided seed selection
- Integration with fuzzing tools (AFL++, LibFuzzer)
