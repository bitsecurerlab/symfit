#!/usr/bin/env node
/**
 * Run SymFit campaign on test binary using MCP server
 */

import { spawn } from "child_process";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const TEST_BINARY = path.join(__dirname, "tests/symfit/test");
const CORPUS_DIR = path.join(__dirname, "test-corpus");
const WORK_DIR = path.join(__dirname, "mcp-workdir");

async function runCampaign() {
  console.log("=== SymFit Test Campaign ===\n");
  console.log(`Binary: ${TEST_BINARY}`);
  console.log(`Corpus: ${CORPUS_DIR}`);
  console.log(`Work dir: ${WORK_DIR}\n`);

  // Clean up previous test data
  try {
    await fs.rm(CORPUS_DIR, { recursive: true, force: true });
    await fs.rm(WORK_DIR, { recursive: true, force: true });
    await fs.mkdir(CORPUS_DIR, { recursive: true });
    await fs.mkdir(WORK_DIR, { recursive: true });
    console.log("✓ Directories cleaned and created\n");
  } catch (e) {
    console.error("Error setting up directories:", e.message);
    process.exit(1);
  }

  // Start MCP server
  console.log("Starting MCP server...\n");
  const serverPath = path.join(__dirname, "mcp-server/index.js");
  const server = spawn("node", [serverPath], {
    stdio: ["pipe", "pipe", "inherit"],
    env: {
      ...process.env,
      SYMFIT_BUILD_DIR: path.join(__dirname, "build"),
      SYMFIT_WORK_DIR: WORK_DIR,
      SYMFIT_USE_DOCKER: "true",
      SYMFIT_DOCKER_IMAGE: "ghcr.io/bitsecurerlab/symfit:latest",
    },
  });

  let responseBuffer = "";
  let requestId = 1;

  server.stdout.on("data", (data) => {
    responseBuffer += data.toString();
  });

  // Helper to send JSON-RPC request
  const sendRequest = async (method, params) => {
    const request = {
      jsonrpc: "2.0",
      id: requestId++,
      method,
      params,
    };
    const requestStr = JSON.stringify(request) + "\n";
    server.stdin.write(requestStr);
  };

  // Wait for server initialization
  await new Promise((resolve) => setTimeout(resolve, 1500));

  // Test 1: Initialize corpus
  console.log("Step 1: Initializing corpus with seed inputs...");
  await sendRequest("tools/call", {
    name: "initialize_corpus",
    arguments: {
      corpus_dir: CORPUS_DIR,
      seeds: ["test", "AAAA", "ABCDEF"],
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 1000));

  // Test 2: Run campaign
  console.log("Step 2: Running symbolic execution campaign (3 rounds)...\n");
  await sendRequest("tools/call", {
    name: "run_campaign",
    arguments: {
      binary_path: TEST_BINARY,
      corpus_dir: CORPUS_DIR,
      max_rounds: 3,
      timeout: 1000,
      campaign_timeout: 60000,
      work_dir: WORK_DIR,
    },
  });

  // Wait for campaign to complete
  await new Promise((resolve) => setTimeout(resolve, 30000));

  // Test 3: Analyze corpus
  console.log("\nStep 3: Analyzing final corpus...\n");
  await sendRequest("tools/call", {
    name: "analyze_corpus",
    arguments: {
      corpus_dir: CORPUS_DIR,
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 1000));

  // Parse and display results
  const responses = responseBuffer.split("\n").filter((line) => line.trim());
  let campaignResult = null;
  let corpusAnalysis = null;

  for (const line of responses) {
    try {
      const parsed = JSON.parse(line);
      if (parsed.result?.content?.[0]?.text) {
        const result = JSON.parse(parsed.result.content[0].text);

        // Identify response type
        if (result.coverage_progression) {
          campaignResult = result;
        } else if (result.total_files !== undefined) {
          corpusAnalysis = result;
        }
      }
    } catch (e) {
      // Skip non-JSON or malformed lines
    }
  }

  // Display results
  console.log("\n=== Campaign Results ===\n");

  if (campaignResult) {
    console.log(`Total rounds: ${campaignResult.rounds?.length || 0}`);
    console.log(`Test cases generated: ${campaignResult.total_cases_generated}`);
    console.log(`Final corpus size: ${campaignResult.final_corpus_size}`);
    console.log(`Time elapsed: ${campaignResult.elapsed_time_seconds}s`);
    console.log(`Stop reason: ${campaignResult.stop_reason || "completed"}\n`);

    if (campaignResult.final_coverage) {
      console.log("=== Coverage Summary ===\n");
      console.log(`Edges covered: ${campaignResult.final_coverage.total_edges_covered} / ${campaignResult.final_coverage.total_edges}`);
      console.log(`Coverage: ${campaignResult.final_coverage.coverage_percentage}%\n`);
    }

    if (campaignResult.coverage_progression) {
      console.log("=== Coverage Progression ===\n");
      console.log("Round | Edges | New  | Coverage");
      console.log("------|-------|------|----------");
      campaignResult.coverage_progression.forEach((cp) => {
        const round = cp.round.toString().padStart(5);
        const edges = cp.edges_covered.toString().padStart(5);
        const newEdges = cp.new_edges.toString().padStart(4);
        const pct = cp.percentage.toString().padStart(7);
        console.log(`${round} | ${edges} | ${newEdges} | ${pct}%`);
      });
      console.log();
    }

    if (campaignResult.rounds) {
      console.log("=== Round Details ===\n");
      campaignResult.rounds.forEach((round) => {
        console.log(`Round ${round.round}:`);
        console.log(`  Inputs processed: ${round.inputs_processed}`);
        console.log(`  New test cases: ${round.new_cases}`);
        if (round.coverage) {
          console.log(`  New edges: ${round.coverage.edges_discovered_this_round}`);
          console.log(`  Total edges: ${round.coverage.total_edges_covered}`);
        }
        console.log();
      });
    }
  } else {
    console.log("⚠ Campaign results not found in server response");
  }

  if (corpusAnalysis) {
    console.log("=== Corpus Analysis ===\n");
    console.log(`Total files: ${corpusAnalysis.total_files}`);
    console.log(`Total size: ${corpusAnalysis.total_size} bytes`);
    console.log(`Size range: ${corpusAnalysis.size_distribution.min} - ${corpusAnalysis.size_distribution.max} bytes`);
    console.log(`Average size: ${corpusAnalysis.size_distribution.avg.toFixed(2)} bytes\n`);
  }

  // Cleanup
  server.kill();
  console.log("✓ Test completed!");
}

runCampaign().catch((error) => {
  console.error("Campaign failed:", error);
  process.exit(1);
});
