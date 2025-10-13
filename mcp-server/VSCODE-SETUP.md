# VS Code / Claude Code Setup Guide

This guide shows you how to use the SymFit MCP server with VS Code and Claude Code.

## Prerequisites

1. **VS Code with Claude Code extension** installed
2. **SymFit built** - Run `./build.sh` from the project root
3. **Node.js 18+** installed

## Quick Setup (Already Done!)

The MCP server is already configured! Here's what was set up:

### 1. Configuration File Created

A [`.mcp.json`](../.mcp.json) file has been created in the project root with this configuration:

```json
{
  "mcpServers": {
    "symfit": {
      "command": "node",
      "args": ["${workspaceFolder}/mcp-server/index.js"],
      "env": {
        "SYMFIT_BUILD_DIR": "${workspaceFolder}/build",
        "SYMFIT_WORK_DIR": "${workspaceFolder}/mcp-workdir"
      }
    }
  }
}
```

This uses workspace variables (`${workspaceFolder}`), so it will work automatically without hardcoding paths.

### 2. Dependencies Installed

All Node.js dependencies have been installed in `node_modules/`.

### 3. Server Executable

The server script ([index.js](index.js)) is ready to run.

## Using the MCP Server

### Step 1: Reload VS Code

To load the MCP configuration:

1. Open Command Palette: `Cmd/Ctrl + Shift + P`
2. Run: **Developer: Reload Window**

Or simply restart VS Code.

### Step 2: Verify Server is Loaded

The MCP server should now be available in Claude Code. You can verify by asking:

> "What MCP servers are available?"

You should see "symfit" in the list.

### Step 3: Try It Out!

Ask Claude Code to use the SymFit tools:

#### Example 1: List Available Tools
> "Use the SymFit MCP server to list all available tools and what they do"

#### Example 2: Analyze Test Binary
> "Use SymFit to analyze the test binary at `/home/heng/git/symfit/tests/symfit/test`. Run a 3-round campaign and show me what paths were discovered."

#### Example 3: Single Execution
> "Run symbolic execution on the test binary with input 'ABC' and show me what new test cases are generated"

## What Claude Code Will Do

When you ask Claude Code to use SymFit, it will:

1. **Automatically call the MCP server** - No manual commands needed
2. **Use the tools** - Like `run_campaign`, `initialize_corpus`, etc.
3. **Present results** - In a readable format with insights
4. **Handle errors** - If anything goes wrong, it will explain what happened

## Available MCP Tools

The SymFit MCP server provides 6 tools:

| Tool | Purpose |
|------|---------|
| `run_symbolic_execution` | Run symbolic execution on a binary with a specific input |
| `initialize_corpus` | Create a corpus directory with seed inputs |
| `add_to_corpus` | Add test cases to corpus (with deduplication) |
| `run_campaign` | Run iterative symbolic execution (multiple rounds) |
| `analyze_corpus` | Get statistics about a corpus |
| `read_test_case` | Read and inspect a specific test case |

See [README.md](README.md) for detailed documentation of each tool.

## Configuration Details

### Environment Variables

The `.mcp.json` sets these environment variables:

- `SYMFIT_BUILD_DIR`: Points to `build/` in the workspace
- `SYMFIT_WORK_DIR`: Points to `mcp-workdir/` in the workspace

These can be overridden if needed by editing `.mcp.json`.

### Workspace Folder

`${workspaceFolder}` automatically resolves to:
```
/home/heng/git/symfit
```

This means the paths are:
- Build: `/home/heng/git/symfit/build`
- Work: `/home/heng/git/symfit/mcp-workdir`
- Server: `/home/heng/git/symfit/mcp-server/index.js`

## Troubleshooting

### MCP Server Not Found

**Solution**: Reload VS Code window
```
Cmd/Ctrl + Shift + P → "Developer: Reload Window"
```

### "SymFit binaries not found"

**Solution**: Build SymFit first
```bash
cd /home/heng/git/symfit
./build.sh
```

### "Cannot find module @modelcontextprotocol/sdk"

**Solution**: Install dependencies
```bash
cd /home/heng/git/symfit/mcp-server
npm install
```

### Permission Errors

**Solution**: Ensure directories are writable
```bash
chmod -R u+w /home/heng/git/symfit/mcp-workdir
```

### Server Crashes or Timeouts

**Possible causes**:
- Binary is not executable: `chmod +x /path/to/binary`
- Binary is not x86_64 Linux
- Timeout too short for complex programs

**Solution**: Ask Claude Code to increase the timeout:
> "Run symbolic execution with a 2-minute timeout"

## Advanced: Manual MCP Commands

You can also manage MCP servers using the CLI:

### List MCP Servers
```bash
claude mcp list
```

### Add Server Manually
```bash
claude mcp add --transport stdio symfit node mcp-server/index.js
```

### Remove Server
```bash
claude mcp remove symfit
```

### View Configuration
```bash
cat .mcp.json
```

## Project-Level vs User-Level

The `.mcp.json` file is **project-level**, meaning:

✅ Only available in this workspace
✅ Shared with team (if committed to git)
✅ Uses relative paths (portable)

If you want the server available in **all projects**:

```bash
claude mcp add --scope user symfit node /absolute/path/to/symfit/mcp-server/index.js
```

## Sharing with Your Team

To let teammates use the MCP server:

1. **Commit `.mcp.json`** to git (it's already in the project root)
2. **Document in README** - Point them to this guide
3. **Share requirements**:
   - SymFit must be built (`./build.sh`)
   - Node.js dependencies installed (`cd mcp-server && npm install`)
   - VS Code with Claude Code extension

Then teammates just need to:
1. Clone the repo
2. Run `./build.sh`
3. Run `cd mcp-server && npm install`
4. Reload VS Code

## Example Workflows

### Workflow 1: Quick Binary Analysis
```
You: "Analyze /path/to/binary with SymFit, use 5 rounds"
Claude: [Calls initialize_corpus, run_campaign, analyze_corpus]
Claude: "Found 23 unique test cases covering X paths..."
```

### Workflow 2: Debugging Specific Input
```
You: "Run symbolic execution on the test binary with input 'SECRET' and show me what happens"
Claude: [Calls run_symbolic_execution]
Claude: "Generated 3 new test cases: ..."
```

### Workflow 3: Corpus Management
```
You: "Analyze the corpus at ./my-corpus and show me the 5 largest test cases"
Claude: [Calls analyze_corpus, then read_test_case for each]
Claude: "Corpus has 47 files. Here are the 5 largest..."
```

## Next Steps

- Try the examples above
- Read [QUICKSTART.md](QUICKSTART.md) for more examples
- See [EXAMPLES.md](EXAMPLES.md) for 10 detailed use cases
- Check [README.md](README.md) for full documentation

## Getting Help

If something doesn't work:

1. **Check the logs**: Look in `mcp-workdir/` for execution logs
2. **Verify setup**: Run `./test-server.sh` to validate configuration
3. **Ask Claude Code**: "Debug why the SymFit MCP server isn't working"
4. **Check MCP status**: `claude mcp list` to see registered servers

## Resources

- [Model Context Protocol Docs](https://modelcontextprotocol.io/)
- [Claude Code MCP Documentation](https://docs.claude.com/en/docs/claude-code/mcp)
- [SymFit Main README](../README.md)
