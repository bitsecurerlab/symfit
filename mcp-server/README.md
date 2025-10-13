# SymFit MCP Server

An MCP (Model Context Protocol) server that enables LLM agents to perform concolic execution on binaries using the SymFit framework.

## Overview

This MCP server exposes SymFit's symbolic execution capabilities through a standardized interface that LLM agents can use to automatically analyze binaries, discover new execution paths, and generate test cases.

## Features

- **Single Execution**: Run symbolic execution on a binary with a specific input
- **Corpus Management**: Initialize and manage test case corpora with automatic deduplication
- **Campaign Execution**: Run iterative symbolic execution campaigns to systematically explore program paths
- **Analysis Tools**: Analyze corpus statistics and read test cases
- **Automated Workflow**: Handles all the complexity of environment setup, path tracking, and case generation

## Installation

### Prerequisites

1. SymFit must be built first. From the project root:
   ```bash
   ./build.sh
   ```

2. Node.js 18 or higher must be installed.

### Install MCP Server

```bash
cd mcp-server
npm install
```

## Usage

### Running the Server

The MCP server runs over stdio and is typically invoked by an MCP client:

```bash
node index.js
```

Or use it directly with an MCP client like Claude Desktop.

### Environment Variables

- `SYMFIT_BUILD_DIR`: Path to SymFit build directory (default: `../build`)
- `SYMFIT_WORK_DIR`: Working directory for execution (default: `./mcp-workdir`)

### Configuration for VS Code / Claude Code

The easiest way to configure the MCP server in VS Code with Claude Code is to use the `.mcp.json` file in the project root. This file has already been created for you at:

```
/home/heng/git/symfit/.mcp.json
```

The configuration uses workspace variables, so it will work automatically once you:

1. **Install dependencies:**
   ```bash
   cd mcp-server
   npm install
   ```

2. **Reload VS Code** - The MCP server will be automatically detected

3. **Try it out!** Ask Claude Code:
   > "Use the SymFit MCP server to list available tools"

You can also configure it manually using the CLI:

```bash
# From the project root
claude mcp add --transport stdio symfit node mcp-server/index.js
```

### Configuration for Claude Desktop

Add to your Claude Desktop configuration:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "symfit": {
      "command": "node",
      "args": ["/absolute/path/to/symfit/mcp-server/index.js"],
      "env": {
        "SYMFIT_BUILD_DIR": "/absolute/path/to/symfit/build"
      }
    }
  }
}
```

**Important**: Replace `/absolute/path/to/symfit` with the actual absolute path to your symfit directory.

## Available Tools

### 1. `run_symbolic_execution`

Run symbolic execution on a binary with a given input seed.

**Parameters:**
- `binary_path` (required): Absolute path to the target binary
- `input_data` (required): Input data to use as seed
- `build_dir` (optional): Path to SymFit build directory
- `work_dir` (optional): Working directory for execution
- `timeout` (optional): Execution timeout in milliseconds (default: 30000)

**Returns:**
- Exit code
- Standard output/error
- Array of generated test cases (base64 encoded)
- Output directory path

**Example:**
```javascript
{
  "binary_path": "/path/to/binary",
  "input_data": "test",
  "timeout": 60000
}
```

### 2. `initialize_corpus`

Initialize a corpus directory with seed inputs.

**Parameters:**
- `corpus_dir` (required): Path to corpus directory
- `seeds` (optional): Array of seed inputs (default: `["test", "ABCDEF"]`)

**Returns:**
- Corpus directory path
- Number of seeds created
- List of created files

**Example:**
```javascript
{
  "corpus_dir": "/path/to/corpus",
  "seeds": ["input1", "input2", "ABC"]
}
```

### 3. `add_to_corpus`

Add test cases to corpus with automatic deduplication.

**Parameters:**
- `corpus_dir` (required): Path to corpus directory
- `test_cases` (required): Array of test cases with `content` (base64) and optional `source_file`

**Returns:**
- Number of cases added
- Number of duplicates skipped
- Details for each case

**Example:**
```javascript
{
  "corpus_dir": "/path/to/corpus",
  "test_cases": [
    {
      "content": "dGVzdA==",
      "source_file": "generated-001"
    }
  ]
}
```

### 4. `run_campaign`

Run an iterative symbolic execution campaign.

**Parameters:**
- `binary_path` (required): Absolute path to the target binary
- `corpus_dir` (required): Path to corpus directory
- `max_rounds` (optional): Maximum number of rounds (default: 5)
- `build_dir` (optional): Path to SymFit build directory
- `work_dir` (optional): Working directory for execution
- `timeout` (optional): Per-case timeout in milliseconds (default: 30000)

**Returns:**
- Array of round results with statistics
- Total cases generated
- Final corpus size
- Stop reason

**Example:**
```javascript
{
  "binary_path": "/path/to/binary",
  "corpus_dir": "/path/to/corpus",
  "max_rounds": 10
}
```

### 5. `analyze_corpus`

Analyze a corpus and return statistics.

**Parameters:**
- `corpus_dir` (required): Path to corpus directory

**Returns:**
- Total files and size
- Size distribution (min, max, avg)
- List of files with previews

**Example:**
```javascript
{
  "corpus_dir": "/path/to/corpus"
}
```

### 6. `read_test_case`

Read a specific test case from corpus.

**Parameters:**
- `corpus_dir` (required): Path to corpus directory
- `filename` (required): Name of the test case file

**Returns:**
- Filename and hash
- File size
- Content in multiple formats (base64, UTF-8, hex)

**Example:**
```javascript
{
  "corpus_dir": "/path/to/corpus",
  "filename": "a3f8d2e91b0c4f5a6d7e8f9a0b1c2d3e4f5a6b7c"
}
```

## Typical Workflow

Here's how an LLM agent might use this server:

1. **Initialize**: Create a corpus with initial seeds
   ```
   initialize_corpus({ corpus_dir: "./corpus" })
   ```

2. **Run Campaign**: Iteratively explore the binary
   ```
   run_campaign({
     binary_path: "./test_binary",
     corpus_dir: "./corpus",
     max_rounds: 10
   })
   ```

3. **Analyze Results**: Check what was discovered
   ```
   analyze_corpus({ corpus_dir: "./corpus" })
   ```

4. **Examine Cases**: Look at specific interesting test cases
   ```
   read_test_case({
     corpus_dir: "./corpus",
     filename: "specific_hash"
   })
   ```

## How It Works

The MCP server wraps SymFit's core functionality:

1. **Symbolic Execution**: Uses SymFit's modified QEMU (`symqemu-x86_64`) and the `fgtest` driver to run binaries with symbolic inputs

2. **Path Exploration**: For each input, SymFit analyzes branch conditions and generates new inputs that explore different execution paths

3. **Test Case Generation**: New test cases are automatically generated and saved with unique IDs

4. **Deduplication**: Test cases are deduplicated using SHA1 hashing to avoid redundant work

5. **Coverage Tracking**: AFL-style coverage map is maintained to guide exploration

## Example: Using with an LLM Agent

Once configured, you can ask an LLM agent tasks like:

> "Use SymFit to analyze the binary at /path/to/program. Start with the input 'test' and run 5 rounds of symbolic execution. Show me what paths were discovered."

The agent will:
1. Call `initialize_corpus` to set up a test corpus
2. Call `run_campaign` to run symbolic execution
3. Call `analyze_corpus` to report findings
4. Call `read_test_case` to examine interesting cases

## Troubleshooting

### SymFit binaries not found

Make sure SymFit is built:
```bash
cd /path/to/symfit
./build.sh
```

Set the build directory:
```bash
export SYMFIT_BUILD_DIR=/path/to/symfit/build
```

### Binary analysis fails

- Ensure the target binary is executable and accessible
- Check that the binary is compiled for x86_64 Linux
- Increase the timeout for complex programs
- Check SymFit logs in the work directory

### Permission errors

Ensure the MCP server has read/write access to:
- The build directory (for reading SymFit binaries)
- The work directory (for temporary files)
- The corpus directory (for storing test cases)

## Architecture

The server is built on the Model Context Protocol SDK and provides:

- **Stdio Transport**: Communicates via standard input/output
- **Tool-based Interface**: Exposes 6 tools for different operations
- **Async Operations**: All operations are asynchronous and handle timeouts
- **Error Handling**: Comprehensive error handling with meaningful messages

## Security Considerations

This is a defensive security tool designed for:
- Binary analysis and vulnerability research
- Automated test case generation
- Path coverage analysis
- Security auditing

The tool should only be used on binaries you have permission to analyze.

## License

Same as SymFit project.

## References

- [SymFit Paper](https://www.usenix.org/conference/usenixsecurity24/presentation/qi) - USENIX Security 2024
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP Specification
