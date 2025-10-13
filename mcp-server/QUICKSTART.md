# SymFit MCP Server Quick Start

Get started with the SymFit MCP server in 5 minutes.

## Step 1: Build SymFit

If you haven't already, build SymFit from the project root:

```bash
cd /path/to/symfit
./build.sh
```

This will create the build artifacts in `build/`.

## Step 2: Install Dependencies

```bash
cd mcp-server
npm install
```

## Step 3: Test the Server Manually

You can test individual tools using the MCP inspector or by running the server directly:

```bash
# Set environment variables
export SYMFIT_BUILD_DIR=/path/to/symfit/build
export SYMFIT_WORK_DIR=/tmp/symfit-mcp-workdir

# Run the server
node index.js
```

The server will start and wait for JSON-RPC messages on stdin.

## Step 4: Configure Claude Desktop (Optional)

To use with Claude Desktop, edit your configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

Add this configuration:

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

**Important**: Use absolute paths, not relative paths!

Then restart Claude Desktop.

## Step 5: Try It Out!

### Example 1: Analyze the Test Binary

First, make sure the test binary is compiled:

```bash
cd ../tests/symfit
gcc -o test test.c
```

Now ask Claude:

> "Use the SymFit MCP server to analyze the test binary at /path/to/symfit/tests/symfit/test. Initialize a corpus and run a 5-round campaign. Tell me what paths were discovered."

### Example 2: Single Execution

> "Run symbolic execution on /path/to/binary with the input 'ABC' and show me what new test cases are generated."

### Example 3: Corpus Analysis

> "Analyze the corpus at /path/to/corpus and show me statistics about the test cases."

## Understanding the Output

When you run a campaign, you'll see output like:

```json
{
  "rounds": [
    {
      "round": 1,
      "inputs_processed": 2,
      "new_cases": 5,
      "cases": [...]
    },
    {
      "round": 2,
      "inputs_processed": 5,
      "new_cases": 3,
      "cases": [...]
    }
  ],
  "total_cases_generated": 8,
  "final_corpus_size": 10,
  "stop_reason": "no_new_cases"
}
```

This tells you:
- How many rounds were executed
- How many new test cases were found in each round
- Why the campaign stopped (no new cases, max rounds, or empty queue)

## Workflow Examples

### Basic Analysis Workflow

1. **Initialize**: Set up a corpus
   ```
   Tool: initialize_corpus
   Args: { corpus_dir: "./my-corpus" }
   ```

2. **Run**: Execute symbolic execution campaign
   ```
   Tool: run_campaign
   Args: {
     binary_path: "./my-binary",
     corpus_dir: "./my-corpus",
     max_rounds: 10
   }
   ```

3. **Analyze**: Review results
   ```
   Tool: analyze_corpus
   Args: { corpus_dir: "./my-corpus" }
   ```

### Advanced Workflow

1. **Custom Seeds**: Start with specific inputs
   ```
   Tool: initialize_corpus
   Args: {
     corpus_dir: "./corpus",
     seeds: ["USER=admin", "PASS=123", "GET / HTTP/1.1"]
   }
   ```

2. **Targeted Execution**: Run on specific inputs
   ```
   Tool: run_symbolic_execution
   Args: {
     binary_path: "./binary",
     input_data: "malformed-input",
     timeout: 60000
   }
   ```

3. **Manual Addition**: Add interesting cases
   ```
   Tool: add_to_corpus
   Args: {
     corpus_dir: "./corpus",
     test_cases: [
       { content: "...", source_file: "manual-1" }
     ]
   }
   ```

4. **Continue Campaign**: Run more rounds
   ```
   Tool: run_campaign
   Args: {
     binary_path: "./binary",
     corpus_dir: "./corpus",
     max_rounds: 20
   }
   ```

## Common Issues

### "SymFit QEMU binary not found"

The build directory is incorrect. Set it explicitly:

```bash
export SYMFIT_BUILD_DIR=/absolute/path/to/symfit/build
```

### "Target binary not found"

Use absolute paths for binaries:

```json
{
  "binary_path": "/home/user/symfit/tests/symfit/test"
}
```

### "Permission denied"

Make sure:
1. The binary is executable: `chmod +x /path/to/binary`
2. The work directory is writable
3. The corpus directory is writable

### Timeouts

Increase timeout for complex programs:

```json
{
  "timeout": 60000
}
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore the test program at `../tests/symfit/test.c` to understand how SymFit works
- Try analyzing your own binaries
- Experiment with different seed inputs to guide exploration

## Tips

1. **Start Small**: Begin with simple binaries and short campaigns (2-3 rounds)
2. **Use Good Seeds**: Better seed inputs lead to better exploration
3. **Monitor Progress**: Use `analyze_corpus` between rounds to track progress
4. **Increase Rounds**: If discovering new paths, increase `max_rounds`
5. **Check Work Directory**: Look at the work directory to see intermediate files

## Support

For issues with:
- **SymFit**: Check the main [README.md](../README.md)
- **MCP Server**: File an issue with logs from the work directory
- **Claude Desktop**: Check the Claude Desktop MCP documentation

## Resources

- [SymFit Documentation](../README.md)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Example Test Program](../tests/symfit/test.c)
