# Docker Setup for SymFit MCP Server

The SymFit MCP server has been configured to run SymFit commands inside Docker containers, which is required for WSL environments due to dependency issues.

## Configuration

The MCP server is configured with:

- **Docker Mode**: Enabled by default (`SYMFIT_USE_DOCKER=true`)
- **Docker Image**: `ghcr.io/bitsecurerlab/symfit:latest`
- **Container Paths**: `/workspace/build/` (SymFit binaries inside container)
- **User Permissions**: Runs with `--user ${UID}:${GID}` to avoid root ownership issues

## How It Works

When you call SymFit tools through the MCP server:

1. The MCP server prepares the input files in the work directory
2. It launches a Docker container with:
   - **User permissions** (`--user ${UID}:${GID}`) to avoid root ownership issues
   - Work directory mounted at `/workdir`
   - Target binary mounted at `/binary` (read-only)
   - Required environment variables set
3. SymFit runs inside the container
4. Generated test cases are written to the mounted work directory **with correct user ownership**
5. The MCP server collects the results after container exits
6. New cases are added to the corpus for the next round (enabled by correct permissions)

## Testing

### Test Docker Execution

Run the test script to verify Docker setup:

```bash
cd /home/heng/git/symfit/mcp-server
./test-docker.sh
```

This will:
- Check Docker is installed
- Verify the SymFit image exists
- Run a test symbolic execution
- Show generated test cases

### Test MCP Server

Now you can use the MCP server through Claude Code:

```
Use SymFit to analyze the test binary at /home/heng/git/symfit/tests/symfit/test with a 3-round campaign
```

Claude will automatically call the MCP server, which will run SymFit in Docker.

## Configuration Files

### .mcp.json (Project-level)

```json
{
  "mcpServers": {
    "symfit": {
      "command": "node",
      "args": ["${workspaceFolder}/mcp-server/index.js"],
      "env": {
        "SYMFIT_USE_DOCKER": "true",
        "SYMFIT_DOCKER_IMAGE": "ghcr.io/bitsecurerlab/symfit:latest",
        "SYMFIT_WORK_DIR": "${workspaceFolder}/mcp-workdir"
      }
    }
  }
}
```

### ~/.claude.json (Active configuration)

The environment variables are set in your Claude Code configuration:

```json
{
  "env": {
    "SYMFIT_USE_DOCKER": "true",
    "SYMFIT_DOCKER_IMAGE": "ghcr.io/bitsecurerlab/symfit:latest",
    "SYMFIT_WORK_DIR": "/home/heng/git/symfit/mcp-workdir"
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SYMFIT_USE_DOCKER` | `true` | Enable Docker mode (set to `false` for native execution) |
| `SYMFIT_DOCKER_IMAGE` | `ghcr.io/bitsecurerlab/symfit:latest` | Docker image to use |
| `SYMFIT_WORK_DIR` | `./mcp-workdir` | Working directory for execution |
| `SYMFIT_BUILD_DIR` | `./build` | Build directory (only used in native mode) |

## Docker Command Example

When you run symbolic execution, the MCP server executes:

```bash
docker run --rm \
  --user $(id -u):$(id -g) \
  -v /home/heng/git/symfit/mcp-workdir:/workdir \
  -v /path/to/binary:/binary:ro \
  -e "SYMCC_INPUT_FILE=/workdir/testfile" \
  -e "SYMCC_OUTPUT_DIR=/workdir/output" \
  -e "SYMCC_AFL_COVERAGE_MAP=/workdir/covmap" \
  -e "TAINT_OPTIONS=taint_file=/workdir/testfile" \
  -w /workdir \
  ghcr.io/bitsecurerlab/symfit:latest \
  /workspace/build/symsan/bin/fgtest \
  /workspace/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 \
  /binary
```

**Important**: The `--user $(id -u):$(id -g)` flag ensures files created inside the container have the correct ownership, which is **critical for multi-round campaigns** to work properly.

## Why Docker?

SymFit uses a modified QEMU and various system libraries that:
- Have specific version requirements
- May conflict with WSL system libraries
- Require specific kernel features

Running in Docker ensures:
- ✓ Consistent execution environment
- ✓ No dependency conflicts
- ✓ Works on WSL, Linux, and Mac (with Docker Desktop)
- ✓ Isolated from host system

## Native Mode (Optional)

If you want to run natively (not in Docker), set:

```json
{
  "env": {
    "SYMFIT_USE_DOCKER": "false",
    "SYMFIT_BUILD_DIR": "/path/to/symfit/build"
  }
}
```

**Note**: Native mode only works if SymFit is built on your system and all dependencies are met.

## Troubleshooting

### Docker image not found

Pull the image:
```bash
docker pull ghcr.io/bitsecurerlab/symfit:latest
```

### Permission errors

Ensure Docker has permissions to:
- Read the binary file
- Read/write the work directory

### Timeout errors

Increase timeout in the MCP tool call:
```json
{
  "timeout": 60000
}
```

### Container exits immediately

Check Docker logs:
```bash
docker logs <container-id>
```

Or run the test script with debugging:
```bash
./test-docker.sh
```

## Next Steps

1. Test the Docker setup: `./test-docker.sh`
2. Verify MCP connection: `claude mcp list`
3. Try analyzing a binary through Claude Code
4. Check results in `/home/heng/git/symfit/mcp-workdir/`

## Resources

- [Docker Documentation](https://docs.docker.com/)
- [SymFit README](../README.md)
- [MCP Server README](README.md)
- [Quick Start Guide](QUICKSTART.md)
