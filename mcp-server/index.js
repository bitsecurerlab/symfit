#!/usr/bin/env node

/**
 * SymFit MCP Server
 *
 * This MCP server allows LLM agents to perform concolic execution on binaries
 * using the SymFit framework. It provides tools for:
 * - Running symbolic execution on binaries
 * - Managing test corpus
 * - Analyzing generated test cases
 * - Monitoring execution progress
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "child_process";
import { promisify } from "util";
import { exec as execCallback } from "child_process";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

const exec = promisify(execCallback);

// Configuration
const DEFAULT_BUILD_DIR = process.env.SYMFIT_BUILD_DIR || path.join(process.cwd(), "build");
const DEFAULT_WORK_DIR = process.env.SYMFIT_WORK_DIR || path.join(process.cwd(), "mcp-workdir");
const USE_DOCKER = process.env.SYMFIT_USE_DOCKER !== "false"; // Default to true
const DOCKER_IMAGE = process.env.SYMFIT_DOCKER_IMAGE || "ghcr.io/bitsecurerlab/symfit:latest";

/**
 * Helper function to ensure directory exists
 */
async function ensureDir(dirPath) {
  try {
    await fs.mkdir(dirPath, { recursive: true });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
}

/**
 * Helper function to get file hash
 */
async function getFileHash(filePath) {
  const content = await fs.readFile(filePath);
  return crypto.createHash("sha1").update(content).digest("hex");
}

/**
 * Read AFL coverage map and calculate metrics
 */
async function readCoverageMap(coverageMapPath) {
  try {
    const mapData = await fs.readFile(coverageMapPath);
    // AFL coverage map is 64KB (65536 bytes)
    const mapSize = 65536;

    let edgesHit = 0;
    const hitCounts = new Map();

    for (let i = 0; i < Math.min(mapData.length, mapSize); i++) {
      const count = mapData[i];
      if (count > 0) {
        edgesHit++;
        hitCounts.set(count, (hitCounts.get(count) || 0) + 1);
      }
    }

    return {
      edges_hit: edgesHit,
      total_edges: mapSize,
      coverage_percentage: ((edgesHit / mapSize) * 100).toFixed(2),
      hit_counts: Object.fromEntries(hitCounts),
    };
  } catch (error) {
    // Coverage map might not exist yet
    return {
      edges_hit: 0,
      total_edges: 65536,
      coverage_percentage: "0.00",
      hit_counts: {},
      error: error.message,
    };
  }
}

/**
 * Run symbolic execution on a binary with a given input
 */
async function runSymbolicExecution(args) {
  const {
    binary_path,
    input_data,
    input_filename = "testfile",
    use_stdin = false,
    build_dir = DEFAULT_BUILD_DIR,
    work_dir = DEFAULT_WORK_DIR,
    timeout = 500,  // Default: 500ms per execution
    use_docker = USE_DOCKER,
  } = args;

  // Validate target binary exists
  try {
    await fs.access(binary_path);
  } catch {
    throw new Error(`Target binary not found at: ${binary_path}`);
  }

  // Setup working directories
  await ensureDir(work_dir);
  const outputDir = path.join(work_dir, "output");
  const coverageMap = path.join(work_dir, "covmap");
  const inputFile = path.join(work_dir, input_filename);

  await ensureDir(outputDir);

  // Clear output directory before execution to avoid mixing results
  const existingOutputs = await fs.readdir(outputDir);
  for (const file of existingOutputs) {
    if (file.startsWith("id-")) {
      await fs.unlink(path.join(outputDir, file));
    }
  }

  // Write input data (always write to file, even for stdin mode)
  // SymFit will read from this file to get the symbolic input
  if (typeof input_data === "string") {
    await fs.writeFile(inputFile, input_data, "utf8");
  } else if (Buffer.isBuffer(input_data)) {
    await fs.writeFile(inputFile, input_data);
  } else {
    await fs.writeFile(inputFile, String(input_data), "utf8");
  }

  if (use_docker) {
    // Run via Docker
    return runSymbolicExecutionDocker({
      binary_path,
      work_dir,
      outputDir,
      coverageMap,
      inputFile,
      input_filename,
      use_stdin,
      timeout,
    });
  } else {
    // Run natively (original implementation)
    const symfit = path.join(build_dir, "symfit-symsan/x86_64-linux-user/symqemu-x86_64");
    const fgtest = path.join(build_dir, "symsan/bin/fgtest");

    try {
      await fs.access(symfit);
    } catch {
      throw new Error(`SymFit QEMU binary not found at: ${symfit}`);
    }

    try {
      await fs.access(fgtest);
    } catch {
      throw new Error(`fgtest binary not found at: ${fgtest}`);
    }

    const env = {
      ...process.env,
      SYMCC_INPUT_FILE: inputFile,
      SYMCC_OUTPUT_DIR: outputDir,
      SYMCC_AFL_COVERAGE_MAP: coverageMap,
      TAINT_OPTIONS: `taint_file=${inputFile}`,
    };

    return new Promise((resolve, reject) => {
      const proc = spawn(fgtest, [symfit, binary_path], {
        env,
        cwd: work_dir,
        timeout,
      });

      let stdout = "";
      let stderr = "";

      proc.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      proc.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      proc.on("close", async (code) => {
        try {
          const generatedCases = await collectGeneratedCases(outputDir);
          const coverage = await readCoverageMap(coverageMap);
          resolve({
            exit_code: code,
            stdout,
            stderr,
            generated_cases: generatedCases,
            output_dir: outputDir,
            coverage,
          });
        } catch (error) {
          reject(error);
        }
      });

      proc.on("error", (error) => {
        reject(error);
      });
    });
  }
}

/**
 * Run symbolic execution using Docker
 */
async function runSymbolicExecutionDocker(args) {
  const { binary_path, work_dir, outputDir, coverageMap, inputFile, input_filename, use_stdin, timeout } = args;

  // Docker paths (inside container)
  const dockerWorkDir = "/workdir";
  const dockerBinaryPath = "/binary";
  const dockerInputFile = `${dockerWorkDir}/${input_filename}`;
  const dockerOutputDir = `${dockerWorkDir}/output`;
  const dockerCoverageMap = `${dockerWorkDir}/covmap`;

  // Get current user UID and GID for Docker
  // This ensures files created in Docker have correct permissions
  const uid = process.getuid ? process.getuid() : 1000;
  const gid = process.getgid ? process.getgid() : 1000;

  // Build docker command
  const dockerArgs = [
    "run",
    "--rm",
    "--user", `${uid}:${gid}`,
  ];

  // Add stdin mode if requested
  if (use_stdin) {
    dockerArgs.push("-i");  // Interactive mode for stdin
  }

  dockerArgs.push(
    "-v", `${work_dir}:${dockerWorkDir}`,
    "-v", `${binary_path}:${dockerBinaryPath}:ro`,
    "-e", `SYMCC_INPUT_FILE=${dockerInputFile}`,
    "-e", `SYMCC_OUTPUT_DIR=${dockerOutputDir}`,
    "-e", `SYMCC_AFL_COVERAGE_MAP=${dockerCoverageMap}`,
    "-e", `TAINT_OPTIONS=taint_file=${dockerInputFile}`,
    "-w", dockerWorkDir,
    DOCKER_IMAGE,
  );

  // If stdin mode, redirect input file to stdin using shell
  if (use_stdin) {
    dockerArgs.push(
      "/bin/sh",
      "-c",
      `cat ${dockerInputFile} | /workspace/build/symsan/bin/fgtest /workspace/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 ${dockerBinaryPath}`
    );
  } else {
    dockerArgs.push(
      "/workspace/build/symsan/bin/fgtest",
      "/workspace/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64",
      dockerBinaryPath
    );
  }

  return new Promise((resolve, reject) => {
    const proc = spawn("docker", dockerArgs, {
      timeout,
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", async (code) => {
      try {
        const generatedCases = await collectGeneratedCases(outputDir);
        const coverage = await readCoverageMap(coverageMap);
        resolve({
          exit_code: code,
          stdout,
          stderr,
          generated_cases: generatedCases,
          output_dir: outputDir,
          execution_mode: "docker",
          coverage,
        });
      } catch (error) {
        reject(error);
      }
    });

    proc.on("error", (error) => {
      reject(error);
    });
  });
}

/**
 * Collect generated test cases from output directory
 */
async function collectGeneratedCases(outputDir) {
  const files = await fs.readdir(outputDir);
  const generatedCases = [];

  for (const file of files) {
    if (file.startsWith("id-0-0-")) {
      const filePath = path.join(outputDir, file);
      const content = await fs.readFile(filePath);
      const hash = crypto.createHash("sha1").update(content).digest("hex");
      generatedCases.push({
        filename: file,
        hash,
        size: content.length,
        content: content.toString("base64"),
      });
    }
  }

  return generatedCases;
}

/**
 * Initialize a corpus directory with seed inputs
 */
async function initializeCorpus(args) {
  const { corpus_dir, seeds = ["test", "ABCDEF"] } = args;

  await ensureDir(corpus_dir);

  const createdFiles = [];
  for (let i = 0; i < seeds.length; i++) {
    const seedFile = path.join(corpus_dir, `seed${i + 1}`);
    await fs.writeFile(seedFile, seeds[i], "utf8");
    createdFiles.push(seedFile);
  }

  return {
    corpus_dir,
    seeds_created: createdFiles.length,
    files: createdFiles,
  };
}

/**
 * Add test cases to corpus with deduplication
 */
async function addToCorpus(args) {
  const { corpus_dir, test_cases } = args;

  await ensureDir(corpus_dir);

  const added = [];
  const duplicates = [];

  for (const testCase of test_cases) {
    const { content, source_file } = testCase;
    const buffer = Buffer.from(content, "base64");
    const hash = crypto.createHash("sha1").update(buffer).digest("hex");
    const targetPath = path.join(corpus_dir, hash);

    try {
      await fs.access(targetPath);
      duplicates.push({ hash, source_file });
    } catch {
      await fs.writeFile(targetPath, buffer);
      added.push({ hash, source_file, path: targetPath });
    }
  }

  return {
    added: added.length,
    duplicates: duplicates.length,
    details: { added, duplicates },
  };
}

/**
 * Run iterative symbolic execution campaign
 */
async function runCampaign(args) {
  const {
    binary_path,
    corpus_dir,
    input_filename = "testfile",
    use_stdin = false,
    max_rounds = 5,
    build_dir = DEFAULT_BUILD_DIR,
    work_dir = DEFAULT_WORK_DIR,
    timeout = 500,  // Per-execution timeout: 500ms (should be small)
    campaign_timeout = 300000,  // Total campaign timeout: 5 minutes
  } = args;

  await ensureDir(corpus_dir);

  // Check if corpus is empty
  const corpusFiles = await fs.readdir(corpus_dir);
  if (corpusFiles.length === 0) {
    // Initialize with default seeds
    await initializeCorpus({ corpus_dir });
  }

  const results = {
    rounds: [],
    total_cases_generated: 0,
    final_corpus_size: 0,
    coverage_progression: [],
  };

  // Track campaign start time for total timeout
  const campaignStartTime = Date.now();

  // Track global coverage across all rounds
  const globalCoverage = new Uint8Array(65536); // AFL map size
  let totalEdgesCovered = 0;

  // Track which files to process in next round
  let queueFiles = await fs.readdir(corpus_dir);

  for (let round = 1; round <= max_rounds; round++) {
    // Check if we've exceeded total campaign timeout
    const elapsedTime = Date.now() - campaignStartTime;
    if (elapsedTime >= campaign_timeout) {
      results.stop_reason = "campaign_timeout";
      results.elapsed_time_ms = elapsedTime;
      break;
    }
    if (queueFiles.length === 0) {
      results.stop_reason = "empty_queue";
      break;
    }

    const roundResult = {
      round,
      inputs_processed: queueFiles.length,
      new_cases: 0,
      cases: [],
      coverage: {
        edges_discovered_this_round: 0,
        total_edges_covered: 0,
      },
    };

    const nextQueue = [];
    let newEdgesThisRound = 0;

    for (const file of queueFiles) {
      const inputPath = path.join(corpus_dir, file);
      const inputData = await fs.readFile(inputPath);

      try {
        const execResult = await runSymbolicExecution({
          binary_path,
          input_data: inputData,
          input_filename,
          use_stdin,
          build_dir,
          work_dir,
          timeout,
        });

        // Add new cases to corpus
        const newCases = [];
        for (const generated of execResult.generated_cases) {
          const targetPath = path.join(corpus_dir, generated.hash);
          try {
            await fs.access(targetPath);
            // Already exists
          } catch {
            const buffer = Buffer.from(generated.content, "base64");
            await fs.writeFile(targetPath, buffer);
            newCases.push(generated.hash);
            nextQueue.push(generated.hash);
            roundResult.new_cases++;
          }
        }

        // Merge coverage data from this execution
        if (execResult.coverage && execResult.coverage.edges_hit > 0) {
          try {
            const coverageMapPath = path.join(work_dir, "covmap");
            const mapData = await fs.readFile(coverageMapPath);
            for (let i = 0; i < Math.min(mapData.length, 65536); i++) {
              if (mapData[i] > 0 && globalCoverage[i] === 0) {
                globalCoverage[i] = 1;
                newEdgesThisRound++;
                totalEdgesCovered++;
              }
            }
          } catch (error) {
            // Coverage map read failed, skip
          }
        }

        roundResult.cases.push({
          input_file: file,
          exit_code: execResult.exit_code,
          new_cases: newCases,
          coverage: execResult.coverage,
        });
      } catch (error) {
        roundResult.cases.push({
          input_file: file,
          error: error.message,
        });
      }
    }

    // Update coverage metrics for this round
    roundResult.coverage.edges_discovered_this_round = newEdgesThisRound;
    roundResult.coverage.total_edges_covered = totalEdgesCovered;
    roundResult.coverage.coverage_percentage = ((totalEdgesCovered / 65536) * 100).toFixed(2);

    results.rounds.push(roundResult);
    results.total_cases_generated += roundResult.new_cases;

    // Track coverage progression
    results.coverage_progression.push({
      round,
      edges_covered: totalEdgesCovered,
      new_edges: newEdgesThisRound,
      percentage: roundResult.coverage.coverage_percentage,
    });

    if (roundResult.new_cases === 0) {
      results.stop_reason = "no_new_cases";
      break;
    }

    queueFiles = nextQueue;
  }

  const finalCorpus = await fs.readdir(corpus_dir);
  results.final_corpus_size = finalCorpus.length;

  // Calculate total elapsed time
  const totalElapsedTime = Date.now() - campaignStartTime;
  results.elapsed_time_ms = totalElapsedTime;
  results.elapsed_time_seconds = (totalElapsedTime / 1000).toFixed(2);

  // Final coverage summary
  results.final_coverage = {
    total_edges_covered: totalEdgesCovered,
    total_edges: 65536,
    coverage_percentage: ((totalEdgesCovered / 65536) * 100).toFixed(2),
  };

  return results;
}

/**
 * Analyze corpus statistics
 */
async function analyzeCorpus(args) {
  const { corpus_dir } = args;

  try {
    const files = await fs.readdir(corpus_dir);
    const stats = {
      total_files: files.length,
      total_size: 0,
      size_distribution: {
        min: Infinity,
        max: 0,
        avg: 0,
      },
      files: [],
    };

    for (const file of files) {
      const filePath = path.join(corpus_dir, file);
      const stat = await fs.stat(filePath);
      const content = await fs.readFile(filePath);

      stats.total_size += stat.size;
      stats.size_distribution.min = Math.min(stats.size_distribution.min, stat.size);
      stats.size_distribution.max = Math.max(stats.size_distribution.max, stat.size);

      stats.files.push({
        name: file,
        size: stat.size,
        preview: content.slice(0, 32).toString("base64"),
      });
    }

    if (stats.total_files > 0) {
      stats.size_distribution.avg = stats.total_size / stats.total_files;
    } else {
      stats.size_distribution.min = 0;
    }

    return stats;
  } catch (error) {
    throw new Error(`Failed to analyze corpus: ${error.message}`);
  }
}

/**
 * Read a test case from corpus
 */
async function readTestCase(args) {
  const { corpus_dir, filename } = args;
  const filePath = path.join(corpus_dir, filename);

  try {
    const content = await fs.readFile(filePath);
    const hash = crypto.createHash("sha1").update(content).digest("hex");

    return {
      filename,
      hash,
      size: content.length,
      content: content.toString("base64"),
      content_utf8: content.toString("utf8"),
      content_hex: content.toString("hex"),
    };
  } catch (error) {
    throw new Error(`Failed to read test case: ${error.message}`);
  }
}

// Create MCP server instance
const server = new Server(
  {
    name: "symfit-mcp-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "run_symbolic_execution",
        description:
          "Run symbolic execution on a binary with a given input. This generates new test cases that explore different execution paths. Returns generated test cases and coverage metrics (edges hit, coverage percentage).",
        inputSchema: {
          type: "object",
          properties: {
            binary_path: {
              type: "string",
              description: "Absolute path to the target binary to analyze",
            },
            input_data: {
              type: "string",
              description: "Input data to use as seed",
            },
            input_filename: {
              type: "string",
              description: "Name of the input file the binary expects to read (default: 'testfile'). Ignored if use_stdin is true.",
            },
            use_stdin: {
              type: "boolean",
              description: "If true, pipe input to binary's stdin instead of using a file (default: false)",
            },
            build_dir: {
              type: "string",
              description: "Path to SymFit build directory (default: $SYMFIT_BUILD_DIR or ./build)",
            },
            work_dir: {
              type: "string",
              description: "Working directory for execution (default: $SYMFIT_WORK_DIR or ./mcp-workdir)",
            },
            timeout: {
              type: "number",
              description: "Execution timeout in milliseconds (default: 500ms)",
            },
          },
          required: ["binary_path", "input_data"],
        },
      },
      {
        name: "initialize_corpus",
        description:
          "Initialize a corpus directory with seed inputs for testing. The corpus is used to store test cases.",
        inputSchema: {
          type: "object",
          properties: {
            corpus_dir: {
              type: "string",
              description: "Path to corpus directory to initialize",
            },
            seeds: {
              type: "array",
              items: { type: "string" },
              description: "Array of seed inputs to initialize corpus (default: ['test', 'ABCDEF'])",
            },
          },
          required: ["corpus_dir"],
        },
      },
      {
        name: "add_to_corpus",
        description:
          "Add test cases to corpus with automatic deduplication using SHA1 hashing. Duplicate test cases are skipped.",
        inputSchema: {
          type: "object",
          properties: {
            corpus_dir: {
              type: "string",
              description: "Path to corpus directory",
            },
            test_cases: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  content: {
                    type: "string",
                    description: "Base64-encoded test case content",
                  },
                  source_file: {
                    type: "string",
                    description: "Source filename for reference",
                  },
                },
                required: ["content"],
              },
              description: "Array of test cases to add",
            },
          },
          required: ["corpus_dir", "test_cases"],
        },
      },
      {
        name: "run_campaign",
        description:
          "Run an iterative symbolic execution campaign. This repeatedly runs symbolic execution on corpus inputs, generates new test cases, and adds them to the corpus until no new cases are found or max_rounds is reached. Returns detailed coverage progression showing edges discovered per round, total coverage percentage, and per-input coverage metrics.",
        inputSchema: {
          type: "object",
          properties: {
            binary_path: {
              type: "string",
              description: "Absolute path to the target binary to analyze",
            },
            corpus_dir: {
              type: "string",
              description: "Path to corpus directory (will be initialized if empty)",
            },
            input_filename: {
              type: "string",
              description: "Name of the input file the binary expects to read (default: 'testfile'). Ignored if use_stdin is true.",
            },
            use_stdin: {
              type: "boolean",
              description: "If true, pipe input to binary's stdin instead of using a file (default: false)",
            },
            max_rounds: {
              type: "number",
              description: "Maximum number of rounds to run (default: 5)",
            },
            build_dir: {
              type: "string",
              description: "Path to SymFit build directory (default: $SYMFIT_BUILD_DIR or ./build)",
            },
            work_dir: {
              type: "string",
              description: "Working directory for execution (default: $SYMFIT_WORK_DIR or ./mcp-workdir)",
            },
            timeout: {
              type: "number",
              description: "Per-execution timeout in milliseconds - how long each symbolic execution can run (default: 500ms)",
            },
            campaign_timeout: {
              type: "number",
              description: "Total campaign timeout in milliseconds - maximum time for the entire campaign (default: 300000ms = 5 minutes)",
            },
          },
          required: ["binary_path", "corpus_dir"],
        },
      },
      {
        name: "analyze_corpus",
        description:
          "Analyze a corpus directory and return statistics about the test cases including file count, sizes, and previews.",
        inputSchema: {
          type: "object",
          properties: {
            corpus_dir: {
              type: "string",
              description: "Path to corpus directory to analyze",
            },
          },
          required: ["corpus_dir"],
        },
      },
      {
        name: "read_test_case",
        description:
          "Read a specific test case from the corpus and return its content in multiple formats (base64, UTF-8, hex).",
        inputSchema: {
          type: "object",
          properties: {
            corpus_dir: {
              type: "string",
              description: "Path to corpus directory",
            },
            filename: {
              type: "string",
              description: "Name of the test case file to read",
            },
          },
          required: ["corpus_dir", "filename"],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result;

    switch (name) {
      case "run_symbolic_execution":
        result = await runSymbolicExecution(args);
        break;

      case "initialize_corpus":
        result = await initializeCorpus(args);
        break;

      case "add_to_corpus":
        result = await addToCorpus(args);
        break;

      case "run_campaign":
        result = await runCampaign(args);
        break;

      case "analyze_corpus":
        result = await analyzeCorpus(args);
        break;

      case "read_test_case":
        result = await readTestCase(args);
        break;

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: error.message }, null, 2),
        },
      ],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SymFit MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
