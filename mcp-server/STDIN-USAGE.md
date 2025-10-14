# Stdin Input Mode Usage Guide

SymFit MCP Server now supports analyzing binaries that read from stdin instead of files!

## Overview

Many command-line programs read input from stdin rather than files:
- **Filters**: `grep`, `sed`, `awk`
- **Parsers**: `jq`, `xmllint`, JSON/XML parsers
- **Command-line tools**: Many utilities that process piped input
- **Network services**: Protocol handlers, parsers

Previously, the MCP server only supported programs that read from files. Now you can analyze stdin-reading programs too!

## How It Works

### File Mode (Default)
```
Binary reads from: /workdir/testfile
SymFit tracks: /workdir/testfile
```

### Stdin Mode (New!)
```
Input written to: /workdir/testfile
SymFit tracks: /workdir/testfile
Input piped to: binary's stdin
Binary reads from: stdin
```

**Important**: Even in stdin mode, SymFit still needs a file to track symbolic bytes. The file is created, tracked by SymFit, then piped to the binary's stdin.

## Usage Examples

### Example 1: Simple Stdin Program

**Program (`stdin_example.c`):**
```c
#include <stdio.h>

int main() {
    char buf[32];
    fread(buf, 1, sizeof(buf), stdin);  // Reads from stdin

    if (buf[0] == 'H') puts("Found H");
    if (buf[1] == 'E') puts("Found HE");
    if (buf[2] == 'L') puts("Found HEL");
    if (buf[3] == 'L') puts("Found HELL");
    if (buf[4] == 'O') puts("Found HELLO");

    return 0;
}
```

**MCP Call:**
```javascript
{
  "binary_path": "/path/to/stdin_example",
  "input_data": "test",
  "use_stdin": true  // ← Enable stdin mode
}
```

### Example 2: Campaign with Stdin

```javascript
{
  "binary_path": "/path/to/filter_program",
  "corpus_dir": "./corpus",
  "use_stdin": true,  // ← All executions use stdin
  "max_rounds": 10
}
```

### Example 3: JSON Parser

**Analyzing a JSON parser that reads from stdin:**

```javascript
{
  "binary_path": "/usr/bin/my_json_parser",
  "input_data": "{\"key\": \"value\"}",
  "use_stdin": true,
  "timeout": 60000
}
```

### Example 4: Mixing File and Stdin Modes

**Some programs can read from both:**

```c
int main(int argc, char **argv) {
    FILE *f = (argc > 1) ? fopen(argv[1], "r") : stdin;
    // ...
}
```

For file mode:
```javascript
{
  "binary_path": "/path/to/program",
  "input_data": "test",
  "input_filename": "data.txt",
  "use_stdin": false  // Program will try to open data.txt
}
```

For stdin mode:
```javascript
{
  "binary_path": "/path/to/program",
  "input_data": "test",
  "use_stdin": true  // Program reads from stdin
}
```

## Docker Command Details

### Without Stdin (File Mode)
```bash
docker run ... \
  -e "SYMCC_INPUT_FILE=/workdir/testfile" \
  -e "TAINT_OPTIONS=taint_file=/workdir/testfile" \
  symfit:latest \
  fgtest symqemu /binary
```

### With Stdin Mode
```bash
docker run ... -i \
  -e "SYMCC_INPUT_FILE=/workdir/testfile" \
  -e "TAINT_OPTIONS=taint_file=/workdir/testfile" \
  symfit:latest \
  /bin/sh -c "cat /workdir/testfile | fgtest symqemu /binary"
```

The `-i` flag enables interactive mode for stdin piping.

## Testing

Test the stdin mode:

```bash
cd mcp-server
./test-stdin.sh
```

This will:
1. Create a test program that reads from stdin
2. Compile it statically
3. Run symbolic execution with stdin mode
4. Verify test cases are generated

## Common Patterns

### Pattern 1: Command-Line Filter

```javascript
// Analyzing 'grep'-like program
{
  "binary_path": "/path/to/my_grep",
  "input_data": "search\nthis\ntext\n",
  "use_stdin": true,
  "max_rounds": 5
}
```

### Pattern 2: Protocol Parser

```javascript
// Analyzing HTTP request parser
{
  "binary_path": "/path/to/http_parser",
  "input_data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "use_stdin": true,
  "timeout": 30000
}
```

### Pattern 3: Data Format Parser

```javascript
// Analyzing CSV parser
{
  "binary_path": "/path/to/csv_parser",
  "input_data": "name,age,city\nAlice,30,NYC\n",
  "use_stdin": true
}
```

## Limitations

1. **Binary must be statically linked** (or compatible with Docker container's GLIBC)
   - Solution: Compile with `-static` flag
   - Or: Use compatible toolchain

2. **No interactive input**
   - Stdin is piped once at startup
   - Program cannot read additional input interactively

3. **Single stdin stream**
   - All input provided at once
   - Cannot simulate multiple read() calls with pauses

## Troubleshooting

### Test Cases Not Generated

**Problem**: `use_stdin: true` but no test cases generated

**Solutions**:
1. Verify binary actually reads from stdin (test manually: `echo "test" | ./binary`)
2. Check binary is executable and compatible with Docker container
3. Increase timeout if program is slow
4. Check program doesn't immediately exit without reading

### GLIBC Version Errors

**Problem**: `GLIBC_2.34 not found`

**Solution**: Compile binary statically:
```bash
gcc -static -o program program.c
```

### Permission Errors

**Problem**: Cannot execute binary inside container

**Solution**: Ensure binary is executable:
```bash
chmod +x /path/to/binary
```

## When to Use Stdin Mode

✅ **Use stdin mode when:**
- Program reads from `stdin` (not files)
- Program is a filter (reads stdin, writes stdout)
- Program is invoked like: `cat input | program`
- Program uses `fread(buf, size, 1, stdin)`
- Program calls `read(STDIN_FILENO, ...)`

❌ **Don't use stdin mode when:**
- Program reads from files via `fopen(filename, "r")`
- Program takes filename as command-line argument
- Program reads from specific file paths
- Default file mode (`use_stdin: false`) works

## Comparison

| Feature | File Mode | Stdin Mode |
|---------|-----------|------------|
| Input Source | File at specified path | Piped to stdin |
| `input_filename` | Used | Ignored |
| Docker `-i` flag | No | Yes |
| Command | `fgtest symqemu /binary` | `cat file \| fgtest symqemu /binary` |
| Use Case | File-reading programs | Stdin-reading programs |
| Default | ✓ Yes | No |

## Advanced Usage

### Combining with Custom Filenames

```javascript
// Even though we use stdin, SymFit still tracks a file
{
  "binary_path": "/path/to/binary",
  "input_data": "test",
  "input_filename": "tracked_input.dat",  // File created for tracking
  "use_stdin": true  // But input piped to stdin
}
```

### Large Input Data

```javascript
// For large inputs, consider timeout
{
  "binary_path": "/path/to/parser",
  "input_data": large_data_string,
  "use_stdin": true,
  "timeout": 120000  // 2 minutes
}
```

## See Also

- [README.md](README.md) - Main documentation
- [EXAMPLES.md](EXAMPLES.md) - More usage examples
- [test-stdin.sh](test-stdin.sh) - Stdin mode test script
- [CHANGELOG.md](CHANGELOG.md) - Version history

## Support

If you encounter issues with stdin mode:
1. Test your binary manually: `echo "test" | ./binary`
2. Check Docker logs for errors
3. Try file mode first to verify SymFit works with your binary
4. Run `./test-stdin.sh` to verify stdin mode works in general
