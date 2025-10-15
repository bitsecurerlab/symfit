# SymFit Usage Guide

## Environment Setup

### 1. Pull Docker image
```bash
docker pull ghcr.io/bitsecurerlab/symfit:latest
```

### 2. Create and start a container
```bash
docker run -d --name symfit_container -v /home/administrator/tli-test:/workspace ghcr.io/bitsecurerlab/symfit:latest sleep infinity
```

### 3. Verify the environment
```bash
# Enter the container
docker exec -it symfit_container bash

# Check whether SymFit has been built
ls -la /workspace/symfit/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64
ls -la /workspace/symfit/build/symsan/bin/fgtest
```

## Core Components

### Key file locations
- **SymFit main binary**: `/workspace/symfit/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64`  
- **Symsan test driver (fgtest)**: `/workspace/symfit/build/symsan/bin/fgtest`  
- **Symsan compiler (ko-clang)**: `/workspace/symfit/build/symsan/bin/ko-clang`

### Environment variables (explanations)
- `SYMCC_INPUT_FILE` — Path to the input file.  
- `SYMCC_OUTPUT_DIR` — Directory where generated testcases will be written.  
- `SYMCC_AFL_COVERAGE_MAP` — Path to the coverage map file.  
- `TAINT_OPTIONS` — Tainting configuration, format `taint_file=<file_path>`.

---

## Multi-round Iterative Testing

```bash
#!/bin/bash
set -e

# Create test program
cat > /workspace/symfit/test.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(){
  char buf[128]={0};
  FILE *f=fopen("/workspace/symfit/testfile","r");
  if(!f) return 0;
  size_t n=fread(buf,1,sizeof(buf)-1,f);
  if(n<1) return 0;

  if(buf[0]=='A') puts("B1:A"); else puts("B1:!A");
  if(n>5) puts("B2:len>5"); else puts("B2:len<=5");
  if(strstr(buf,"PASS")) puts("B3:PASS"); else puts("B3:!PASS");
  if(n>=3 && buf[1]=='B' && buf[2]=='C') puts("B4:ABC");
  if(buf[n-1]=='\n') puts("B5:LF"); else puts("B5:!LF");
  return 0;
}
EOF

# Compile
gcc -O2 -o /workspace/symfit/test /workspace/symfit/test.c

# Prepare directories
rm -rf /workspace/symfit/output /workspace/symfit/corpus
mkdir -p /workspace/symfit/output /workspace/symfit/corpus

# Create initial seeds
echo 'A' > /workspace/symfit/corpus/seed_A
echo 'Z' > /workspace/symfit/corpus/seed_Z
echo 'PASS' > /workspace/symfit/corpus/seed_PASS
echo 'ABC' > /workspace/symfit/corpus/seed_ABC
echo 'test' > /workspace/symfit/corpus/seed_test

# Multi-round iteration
for round in {1..5}; do
  echo "=== Round $round ==="
  echo "Current corpus size: $(ls /workspace/symfit/corpus/ | wc -l)"
  new_cases=0

  for seed in /workspace/symfit/corpus/*; do
    echo "Using seed: $(basename $seed)"
    cp $seed /workspace/symfit/testfile

    export SYMCC_INPUT_FILE=/workspace/symfit/testfile
    export SYMCC_OUTPUT_DIR=/workspace/symfit/output
    export SYMCC_AFL_COVERAGE_MAP=/workspace/symfit/covmap
    export TAINT_OPTIONS=taint_file=/workspace/symfit/testfile

    /workspace/symfit/build/symsan/bin/fgtest \
      /workspace/symfit/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 \
      /workspace/symfit/test >/dev/null 2>&1

    # Add newly generated cases to the corpus
    for new_file in /workspace/symfit/output/id-0-0-*; do
      if [ -f "$new_file" ]; then
        hash=$(sha1sum $new_file | cut -d' ' -f1)
        if [ ! -f "/workspace/symfit/corpus/$hash" ]; then
          cp $new_file "/workspace/symfit/corpus/$hash"
          echo "  Added new testcase: $(basename $new_file) -> $hash"
          new_cases=$((new_cases + 1))
        fi
      fi
    done
  done

  echo "New cases in round $round: $new_cases"
  if [ $new_cases -eq 0 ]; then
    echo "No new cases generated, stopping iteration"
    break
  fi
done

# Branch coverage statistics
echo "=== Branch coverage statistics ==="
echo "Total corpus size: $(ls /workspace/symfit/corpus/ | wc -l)"
> /workspace/symfit/branch_coverage.txt

for testcase in /workspace/symfit/corpus/*; do
  cp $testcase /workspace/symfit/testfile
  output=$(/workspace/symfit/test 2>&1)
  echo "$output" >> /workspace/symfit/branch_coverage.txt
done

echo "Branch coverage summary:"
sort /workspace/symfit/branch_coverage.txt | uniq -c | sort -nr
```

---

## Branch Coverage Counting

```bash
# Count branch coverage for all testcases
echo "=== Branch coverage statistics ==="
echo "Total corpus size: $(ls corpus/ | wc -l)"
> branch_coverage.txt

for testcase in corpus/*; do
  cp $testcase testfile
  output=$(./test 2>&1)
  echo "$output" >> branch_coverage.txt
done

echo "Branch coverage summary:"
sort branch_coverage.txt | uniq -c | sort -nr
```

---

## Test Results

### Iteration statistics
| Round | Number of input seeds | New cases generated | Cumulative cases |
|-------:|----------------------:|--------------------:|-----------------:|
| Round 1 | 5   | 16  | 21  |
| Round 2 | 21  | 60  | 81  |
| Round 3 | 81  | 131 | 212 |
| Round 4 | 212 | 344 | 556 |
| Round 5 | 556 | 222 | 778 |

### Branch coverage statistics

| Branch | Condition | True branch | False branch | Coverage |
|--------|-----------|------------:|-------------:|---------:|
| **B1** | `buf[0]=='A'` | A: 292 (37.5%) | !A: 486 (62.5%) | ✅ Fully covered |
| **B2** | `n>5` | len>5: 0 (0%) | len<=5: 778 (100%) | ❌ Partially covered (only false) |
| **B3** | `strstr(buf,"PASS")` | PASS: 7 (0.9%) | !PASS: 771 (99.1%) | ✅ Fully covered |
| **B4** | `buf[1]=='B' && buf[2]=='C'` | ABC: 84 (10.8%) | !ABC: 694 (89.2%) | ✅ Fully covered |
| **B5** | `buf[n-1]=='\n'` | LF: 310 (39.8%) | !LF: 468 (60.2%) | ✅ Fully covered |
