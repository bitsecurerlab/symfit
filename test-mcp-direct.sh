#!/bin/bash
# Direct test of MCP server using stdio

cd /home/heng/git/symfit/mcp-server

# Start server and send requests
(
  # Initialize request
  echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_campaign","arguments":{"binary_path":"/home/heng/git/symfit/tests/symfit/test","corpus_dir":"/home/heng/git/symfit/test-corpus","max_rounds":3,"timeout":1000}}}'
  sleep 35
) | SYMFIT_USE_DOCKER=true SYMFIT_DOCKER_IMAGE=ghcr.io/bitsecurerlab/symfit:latest node index.js 2>&1
