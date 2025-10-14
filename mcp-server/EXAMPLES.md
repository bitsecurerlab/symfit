# SymFit MCP Server Examples

This document provides practical examples of using the SymFit MCP server for binary analysis tasks.

## Example 1: Basic Binary Analysis

Analyze the included test binary to understand basic functionality.

### Compile the test binary

```bash
cd ../tests/symfit
gcc -o test test.c
```

### Ask Claude Code

> "Using the SymFit MCP server, analyze the test binary at `/path/to/symfit/tests/symfit/test`. Run a campaign with 5 rounds and tell me what you discover."

### What Happens

The agent will:
1. Call `initialize_corpus` to create a corpus
2. Call `run_campaign` with the binary path
3. Call `analyze_corpus` to examine results
4. Report findings

The test program has 5 branches checking for 'A', length > 5, "PASS", "ABC", and line endings. SymFit discovers inputs triggering different combinations of these branches.

## Example 2: Custom Seed Inputs

Use specific seed inputs to guide exploration toward interesting program behavior.

### Ask Claude Code

> "Initialize a corpus at `./my-corpus` with these seeds: 'A', 'ABCDEF', 'PASS', and 'ABC\n'. Then run a symbolic execution campaign on `/path/to/binary` for 10 rounds."

### Expected Actions

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

**Use Case**: When you have domain knowledge about expected input formats or keywords.

## Example 3: Single-Input Exploration

Test how a specific input behaves and what new paths it discovers.

### Ask Claude Code

> "Run symbolic execution on `/path/to/binary` with the input 'test123' and show me what new test cases are generated."

### Expected Output

```json
{
  "exit_code": 0,
  "stdout": "...",
  "generated_cases": [
    {
      "filename": "id-0-0-0",
      "hash": "a1b2c3...",
      "size": 7,
      "content": "dGVzdDEyMw=="
    }
  ],
  "coverage": {
    "edges_hit": 142,
    "coverage_percentage": "0.22"
  }
}
```

**Use Case**: Understanding single input behavior, debugging exploration issues, quick iteration.

## Example 4: Incremental Analysis

Build up a corpus incrementally over multiple sessions.

### Session 1: Initial Exploration
> "Initialize a corpus at `./corpus` and run 3 rounds on `/path/to/binary`."

### Session 2: Continue from Previous Results
> "Continue the campaign on `/path/to/binary` using the corpus at `./corpus`. Run 10 more rounds."

### Session 3: Add Manual Test Cases
> "Add these test cases to the corpus at `./corpus`: 'malformed', 'edge-case', '@@@@'. Then run 5 more rounds."

**Use Case**: Long-running analysis projects, combining automated and manual testing, resuming interrupted analysis.

## Example 5: Corpus Analysis

Examine what has been discovered.

### Ask Claude Code

> "Analyze the corpus at `./corpus` and show me the top 5 largest test cases."

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

**Use Case**: Understanding corpus composition, finding interesting inputs, preparing test cases for manual review.

## Example 6: Stdin-Reading Programs

Analyze programs that read from stdin instead of files.

### Ask Claude Code

> "Analyze the stdin-reading filter program at `/path/to/filter` using stdin mode. Run 5 rounds with seed 'test'."

### Expected Actions

```json
{
  "binary_path": "/path/to/filter",
  "corpus_dir": "./corpus",
  "use_stdin": true,
  "max_rounds": 5
}
```

**Use Case**: Command-line filters, parsers (JSON, XML), protocol handlers, network services.

See [STDIN-USAGE.md](STDIN-USAGE.md) for detailed stdin mode documentation.

## Example 7: Comparing Binaries

Analyze coverage differences between two versions.

### Ask Claude Code

> "Analyze two binaries: `/path/to/v1` and `/path/to/v2`. For each, run a 5-round campaign starting with the same seeds: 'test', 'ABC'. Compare the number of test cases discovered."

### Expected Output

```
Version 1 Results:
- Final corpus size: 23 cases
- Coverage: 0.45%
- Stopped: max_rounds

Version 2 Results:
- Final corpus size: 19 cases
- Coverage: 0.38%
- Stopped: no_new_cases

Analysis:
Version 1 discovered 4 more unique test cases with higher coverage,
suggesting different control flow or additional branches.
```

**Use Case**: Regression testing, patch analysis, version comparison.

## Common Usage Patterns

### Pattern 1: Explore-Then-Refine

1. Run quick campaign (3 rounds)
2. Analyze results
3. Add targeted seeds based on findings
4. Run longer campaign (10+ rounds)

### Pattern 2: Guided Mutation

1. Start with format-aware seeds
2. Let SymFit explore
3. Manually inspect edge cases
4. Add edge case variants
5. Run more rounds

### Pattern 3: Coverage-Guided Analysis

1. Monitor coverage progression during campaign
2. If coverage plateaus → adjust seeds or stop
3. If coverage grows → continue exploration
4. Focus on inputs yielding highest coverage

## Tips for Effective Usage

1. **Start Small**: Begin with 2-3 rounds, then scale up
2. **Use Good Seeds**: Seeds based on expected format work better than random strings
3. **Monitor Progress**: Check corpus size and coverage between rounds
4. **Inspect Interesting Cases**: Use `read_test_case` to examine specific behaviors
5. **Iterate**: Multiple shorter sessions often work better than one long session
6. **Check Logs**: Look in work directory for detailed execution logs when debugging

## Troubleshooting Examples

### Issue: No new cases after round 1

**Solution**: Try more diverse seeds

```json
{
  "seeds": ["", "a", "abc", "test123", "\x00\x01\x02"]
}
```

### Issue: Timeouts on every case

**Solution**: Increase timeout

```json
{
  "timeout": 5000  // 5 seconds per execution
}
```

### Issue: GLIBC version errors

**Solution**: Compile binary statically

```bash
gcc -static -o program program.c
```

## Next Steps

- Try these examples with your own binaries
- Explore different seed strategies
- Experiment with timeout and round configurations
- Integrate with your existing analysis workflow

For more information:
- [README.md](README.md) - Full documentation
- [STDIN-USAGE.md](STDIN-USAGE.md) - Stdin mode guide
- [CHANGELOG.md](CHANGELOG.md) - Version history
