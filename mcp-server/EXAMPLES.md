# SymFit MCP Server Examples

This document provides detailed examples of using the SymFit MCP server for various binary analysis tasks.

## Example 1: Basic Test Binary Analysis

Analyze the included test binary to understand basic functionality.

### Step 1: Compile the test binary

```bash
cd ../tests/symfit
gcc -o test test.c
```

### Step 2: Ask the LLM agent

> "Using the SymFit MCP server, analyze the test binary at `/home/heng/git/symfit/tests/symfit/test`. Run a campaign with 5 rounds and tell me what you discover."

### Expected Agent Actions

The agent will:

1. Call `initialize_corpus` to create a corpus at a temporary location
2. Call `run_campaign` with the binary path and corpus directory
3. Call `analyze_corpus` to examine the results
4. Report findings back to you

### Expected Output Analysis

The test program has 5 branches:
- Branch 1: Checks if first character is 'A'
- Branch 2: Checks if length > 5
- Branch 3: Checks for "PASS" string
- Branch 4: Checks for "ABC" sequence
- Branch 5: Checks for line ending

SymFit should discover inputs that trigger different combinations of these branches.

## Example 2: Custom Seed Inputs

Use specific seed inputs to guide exploration toward interesting program behavior.

### Ask the LLM agent

> "Initialize a corpus at `./my-corpus` with these seeds: 'A', 'ABCDEF', 'PASS', and 'ABC\n'. Then run a symbolic execution campaign on `/path/to/binary` for 10 rounds."

### Expected Agent Actions

1. Call `initialize_corpus`:
   ```json
   {
     "corpus_dir": "./my-corpus",
     "seeds": ["A", "ABCDEF", "PASS", "ABC\n"]
   }
   ```

2. Call `run_campaign`:
   ```json
   {
     "binary_path": "/path/to/binary",
     "corpus_dir": "./my-corpus",
     "max_rounds": 10
   }
   ```

### Use Case

This is useful when you have domain knowledge about the program (e.g., it expects certain formats or keywords).

## Example 3: Single-Input Exploration

Test how a specific input behaves and what new paths it discovers.

### Ask the LLM agent

> "Run symbolic execution on `/path/to/binary` with the input 'test123' and show me what new test cases are generated."

### Expected Agent Actions

Call `run_symbolic_execution`:
```json
{
  "binary_path": "/path/to/binary",
  "input_data": "test123",
  "timeout": 30000
}
```

### Expected Output

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "generated_cases": [
    {
      "filename": "id-0-0-0",
      "hash": "a1b2c3...",
      "size": 7,
      "content": "dGVzdDEyMw=="
    }
  ],
  "output_dir": "/path/to/mcp-workdir/output"
}
```

### Use Case

Good for:
- Understanding what a single input reveals
- Debugging why certain paths aren't explored
- Quick iteration during analysis

## Example 4: Incremental Analysis

Build up a corpus incrementally over multiple sessions.

### Session 1: Initial Exploration

> "Initialize a corpus at `./corpus` and run 3 rounds on `/path/to/binary`."

### Session 2: Continue from Previous Results

> "Continue the campaign on `/path/to/binary` using the corpus at `./corpus`. Run 10 more rounds."

### Session 3: Add Manual Test Cases

> "Add these test cases to the corpus at `./corpus`: 'malformed', 'edge-case', '@@@@'. Then run 5 more rounds."

### Expected Agent Actions (Session 3)

1. Read each manual test case and encode as base64
2. Call `add_to_corpus`:
   ```json
   {
     "corpus_dir": "./corpus",
     "test_cases": [
       {"content": "bWFsZm9ybWVk", "source_file": "manual-1"},
       {"content": "ZWRnZS1jYXNl", "source_file": "manual-2"},
       {"content": "QEBAQEBAdGVzdA==", "source_file": "manual-3"}
     ]
   }
   ```
3. Call `run_campaign` for 5 more rounds

### Use Case

Useful for:
- Long-running analysis projects
- Combining automated and manual testing
- Resuming interrupted analysis

## Example 5: Corpus Analysis and Inspection

Examine what the fuzzer has discovered.

### Ask the LLM agent

> "Analyze the corpus at `./corpus` and show me the top 5 largest test cases."

### Expected Agent Actions

1. Call `analyze_corpus`:
   ```json
   {
     "corpus_dir": "./corpus"
   }
   ```

2. Sort by size and identify top 5

3. For each of top 5, call `read_test_case`:
   ```json
   {
     "corpus_dir": "./corpus",
     "filename": "hash-of-file"
   }
   ```

4. Present results in a readable format

### Expected Output

```
Corpus Analysis Results:
- Total files: 47
- Total size: 1,234 bytes
- Average size: 26.3 bytes
- Size range: 1 - 128 bytes

Top 5 Largest Test Cases:

1. File: a1b2c3d4... (128 bytes)
   Content (UTF-8): "ABCDEFGHIJKLMNOP..." [truncated]
   Content (Hex): 41 42 43 44 45 46 ...

2. File: e5f6g7h8... (96 bytes)
   ...
```

### Use Case

- Understanding corpus composition
- Finding interesting or anomalous inputs
- Preparing test cases for manual review

## Example 6: Timeout Handling for Complex Programs

Handle programs that take longer to execute.

### Ask the LLM agent

> "Run symbolic execution on the complex binary at `/path/to/complex-binary` with input 'test'. Use a 2-minute timeout."

### Expected Agent Actions

Call `run_symbolic_execution`:
```json
{
  "binary_path": "/path/to/complex-binary",
  "input_data": "test",
  "timeout": 120000
}
```

### Use Case

Some programs have:
- Complex initialization
- Deep call stacks
- Many constraints to solve

Increasing timeout allows SymFit more time to explore paths.

## Example 7: Comparing Two Binaries

Analyze coverage differences between two versions.

### Ask the LLM agent

> "Analyze two binaries: `/path/to/v1` and `/path/to/v2`. For each, run a 5-round campaign starting with the same seeds: 'test', 'ABC'. Compare the number of test cases discovered."

### Expected Agent Actions

1. Initialize corpus-v1 and corpus-v2 with same seeds
2. Run campaigns on both binaries
3. Compare final corpus sizes and statistics
4. Report differences

### Expected Output

```
Version 1 Results:
- Final corpus size: 23 cases
- Total rounds: 5
- Stopped: max_rounds

Version 2 Results:
- Final corpus size: 19 cases
- Total rounds: 3
- Stopped: no_new_cases

Analysis:
Version 1 discovered 4 more unique test cases, suggesting
it may have more branches or a different control flow.
```

### Use Case

- Regression testing (did refactoring change behavior?)
- Patch analysis (what new paths does the patch introduce?)
- Version comparison

## Example 8: Directed Analysis with Custom Build Path

Use a custom build of SymFit.

### Setup

```bash
export SYMFIT_BUILD_DIR=/custom/path/to/build
```

### Ask the LLM agent

> "Using the SymFit build at `/custom/path/to/build`, analyze `/path/to/binary` with a 10-round campaign."

### Expected Agent Actions

The agent passes `build_dir` parameter:
```json
{
  "binary_path": "/path/to/binary",
  "corpus_dir": "./corpus",
  "max_rounds": 10,
  "build_dir": "/custom/path/to/build"
}
```

### Use Case

- Testing different SymFit configurations
- Using specialized builds
- Comparing different symbolic execution backends

## Example 9: Batch Analysis of Multiple Binaries

Analyze several binaries in one request.

### Ask the LLM agent

> "Analyze these three binaries with 3 rounds each: `/path/to/bin1`, `/path/to/bin2`, `/path/to/bin3`. Use the same initial seeds for all. Report which one had the most path coverage."

### Expected Agent Actions

For each binary:
1. Initialize corpus
2. Run 3-round campaign
3. Collect statistics

Then compare and report results.

### Expected Output

```
Analysis Results:

bin1: 15 test cases
bin2: 8 test cases
bin3: 42 test cases

Conclusion: bin3 has the most paths discovered,
suggesting it has more complex control flow.
```

### Use Case

- Comparing multiple implementations
- Finding the most complex variant
- Bulk analysis workflows

## Example 10: Debugging Why Paths Aren't Explored

Investigate why certain branches aren't reached.

### Scenario

You know a binary has a branch checking for "SECRET", but SymFit isn't finding it.

### Ask the LLM agent

> "Run symbolic execution on `/path/to/binary` with these inputs: '', 'S', 'SE', 'SEC', 'SECR', 'SECRE', 'SECRET'. Show me which inputs generate new test cases and what those cases look like."

### Expected Agent Actions

For each input:
1. Call `run_symbolic_execution`
2. Examine generated cases
3. Report findings

### Expected Output

```
Input '': 2 new cases
Input 'S': 1 new case
Input 'SE': 1 new case
Input 'SEC': 0 new cases
Input 'SECR': 3 new cases (found the branch!)
  - Generated: "SECRET"
  - Generated: "SECR\x00"
  - Generated: "SECRX"
...
```

### Use Case

- Debugging exploration issues
- Understanding constraint solving
- Guiding the fuzzer toward specific code

## Tips for Effective Usage

### 1. Start Small
Begin with 2-3 rounds to see if the approach works, then scale up.

### 2. Use Good Seeds
Seeds based on expected input format work better than random strings.

### 3. Monitor Progress
Check corpus size between rounds. If it plateaus early, try different seeds.

### 4. Inspect Interesting Cases
Use `read_test_case` to examine cases that trigger specific behaviors.

### 5. Iterate
Symbolic execution is iterative. Multiple sessions often work better than one long session.

### 6. Check the Logs
Look in the work directory for detailed execution logs when debugging.

## Common Patterns

### Pattern 1: Explore-Then-Refine

```
1. Run quick campaign (3 rounds)
2. Analyze results
3. Add targeted seeds based on findings
4. Run longer campaign (10+ rounds)
```

### Pattern 2: Parallel Exploration

```
1. Split interesting seeds across multiple corpora
2. Run campaigns in parallel (if resources allow)
3. Merge successful corpora
4. Continue with combined corpus
```

### Pattern 3: Guided Mutation

```
1. Start with format-aware seeds
2. Let SymFit explore
3. Manually inspect edge cases
4. Add edge case variants
5. Run more rounds
```

## Integration with Other Tools

The MCP server can be combined with other tools:

### With AFL

1. Use AFL to find initial corpus
2. Import AFL corpus to SymFit corpus
3. Run SymFit to find paths AFL missed
4. Export new cases back to AFL

### With Manual Analysis

1. Reverse engineer binary
2. Identify interesting functions
3. Create seeds targeting those functions
4. Use SymFit to generate comprehensive test suite

### With CI/CD

1. Integrate MCP server into CI pipeline
2. Run campaign on each build
3. Track corpus growth over time
4. Alert on anomalies

## Troubleshooting Examples

### Issue: No new cases after round 1

**Solution**: Try more diverse seeds

```
seeds: ["", "a", "abc", "test123", "\x00\x01\x02"]
```

### Issue: Timeouts on every case

**Solution**: Increase timeout or simplify binary

```json
{
  "timeout": 300000  // 5 minutes
}
```

### Issue: Too many similar cases

**Solution**: SymFit automatically deduplicates by hash, but you can also:
- Use fewer rounds
- Start with more targeted seeds
- Post-process corpus to remove similar cases

## Next Steps

Try these examples with your own binaries, then explore:

- Different seed strategies
- Longer campaigns
- Custom analysis scripts
- Integration with your existing tooling

For more information, see:
- [README.md](README.md) - Full documentation
- [QUICKSTART.md](QUICKSTART.md) - Getting started guide
