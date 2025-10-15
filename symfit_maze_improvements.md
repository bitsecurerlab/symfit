# SymFit Improvements for Maze-Solving

## Executive Summary

Based on the maze-nosleep analysis, SymFit plateaued at 0.02% coverage (16 edges) and failed to discover the 24-move winning solution. This document proposes concrete improvements to make SymFit more effective for maze-solving and similar deep-path exploration problems.

## Current Limitations

### 1. Insufficient Exploration Depth
- **Problem**: Default symbolic execution depth is too shallow
- **Evidence**: Solution requires 24 sequential moves, but SymFit generated mostly 4-6 move sequences
- **Impact**: Cannot reach deep program states where interesting behaviors occur

### 2. Poor Coverage Metrics for Stateful Programs
- **Problem**: Edge coverage doesn't distinguish between "new maze position" vs "same position reached differently"
- **Evidence**: 16 edges covered, but likely visiting the same maze positions repeatedly
- **Impact**: Wasted effort exploring already-known states

### 3. No Exploration Guidance
- **Problem**: Random/coverage-guided mutation doesn't prioritize unexplored areas
- **Evidence**: Round 2-6 generated few new test cases (0-6 per round)
- **Impact**: Gets stuck in local areas instead of exploring the full maze

### 4. Limited Input Alphabet Understanding
- **Problem**: Starts with generic seeds ("test", "ABCDEF") instead of problem-specific characters
- **Evidence**: All generated inputs contained invalid characters
- **Impact**: Wastes time on inputs that fail immediately

## Proposed Improvements

---

## 1. Deep Exploration Mode

### Implementation Strategy

Add a configuration option for deep symbolic execution that prioritizes depth over breadth.

```c++
// Configuration
struct DeepExplorationConfig {
    size_t min_input_length = 20;      // Minimum moves to explore
    size_t max_input_length = 50;      // Maximum moves to explore
    size_t depth_budget = 10000;       // Operations per path
    bool prioritize_long_paths = true; // Prefer extending existing paths
};
```

### Algorithm Changes

**Current approach (breadth-first):**
```
Round 1: Explore all seeds (depth 0-5)
Round 2: Explore all generated (depth 5-10)
Round 3: Explore all generated (depth 10-15)
...
```

**Proposed approach (depth-first with iterative deepening):**
```
Phase 1: Quick exploration (depth 0-10)
Phase 2: Medium exploration (depth 10-20)
Phase 3: Deep exploration (depth 20-40)
Phase 4: Very deep exploration (depth 40+)

Within each phase:
- Take one promising path
- Explore it deeply (add many moves)
- Only switch paths after exhausting current path
```

### Concrete Changes

```python
# In run_campaign
def run_deep_campaign(binary_path, corpus_dir, config):
    """Campaign optimized for deep path exploration"""

    # Phase 1: Bootstrap with short inputs
    for depth_range in [(5, 10), (10, 20), (20, 30), (30, 50)]:
        min_depth, max_depth = depth_range

        # Only explore inputs in current depth range
        candidates = get_inputs_in_depth_range(corpus_dir, min_depth, max_depth)

        for input_file in candidates:
            # For each candidate, try extending it significantly
            test_cases = extend_deeply(input_file, additions=10)

            # Execute and add successful extensions
            for tc in test_cases:
                result = execute_symbolic(tc)
                if result.new_coverage:
                    add_to_corpus(tc)
```

### Expected Impact
- **Before**: Plateaus at depth ~6-8 moves
- **After**: Can explore 20-50 move sequences
- **Coverage improvement**: 10-100x for deep-state bugs

---

## 2. State-Based Coverage Tracking

### Problem Analysis

Traditional edge coverage counts:
```
Position (0,0) → (0,1): Edge A (count: 1)
Position (0,0) → (0,1): Edge A (count: 2) ← Not considered new!
```

But for mazes, we want:
```
Position (0,0) ← New!
Position (0,1) ← New!
Position (0,2) ← New!
```

### Implementation Strategy

Add **state coverage** alongside edge coverage:

```c++
// State tracking structure
struct StateTracker {
    std::unordered_set<uint64_t> visited_states;

    // Hash program state (memory snapshots, register values, etc.)
    uint64_t hash_state(const ExecutionState& state) {
        // For maze: hash player position
        // Could extract from program output or memory
        return hash_memory_region(state, position_variable_address);
    }

    bool is_new_state(const ExecutionState& state) {
        uint64_t hash = hash_state(state);
        return visited_states.insert(hash).second;
    }
};
```

### Heuristic: Output-Based State Detection

For programs that print their state (like our maze):

```python
def extract_state_from_output(output):
    """Parse maze output to extract player position"""

    # Look for player position 'X' in maze visualization
    lines = output.split('\n')
    position = None

    for y, line in enumerate(lines):
        x = line.find('X')
        if x != -1:
            position = (x, y)
            break

    return position

def evaluate_test_case(test_case):
    """Score test case by state coverage, not just edge coverage"""

    result = execute(test_case)

    # Traditional coverage
    new_edges = result.edges_hit - previously_seen_edges

    # State coverage (new!)
    state = extract_state_from_output(result.stdout)
    state_is_new = state not in visited_states

    # Combined score
    score = len(new_edges) * 1.0 + (10.0 if state_is_new else 0.0)

    return score
```

### Expected Impact
- **Before**: 31 test cases, many duplicates visiting same positions
- **After**: Each test case explores a unique maze position
- **Efficiency**: 3-5x reduction in wasted executions

---

## 3. Frontier-Guided Exploration

### Concept

Maintain a "frontier" of unexplored states and actively try to reach them.

```python
class FrontierGuidedExplorer:
    def __init__(self):
        self.visited_positions = set()
        self.frontier = set()  # Positions adjacent to visited

    def update_frontier(self, new_position):
        """Update frontier when we visit a new position"""
        self.visited_positions.add(new_position)

        # Add adjacent positions to frontier
        x, y = new_position
        for dx, dy in [(0,1), (0,-1), (1,0), (-1,0)]:
            adjacent = (x+dx, y+dy)
            if adjacent not in self.visited_positions:
                self.frontier.add(adjacent)

        # Remove from frontier (now visited)
        self.frontier.discard(new_position)

    def score_test_case(self, test_case):
        """Prioritize test cases that reach frontier positions"""

        result = execute(test_case)
        position = extract_position(result.output)

        # High score for frontier positions
        if position in self.frontier:
            return 100.0
        # Medium score for new positions
        elif position not in self.visited_positions:
            return 50.0
        # Low score for revisiting known positions
        else:
            return 1.0
```

### Integration with Symbolic Execution

```c++
// During path exploration
void explore_with_frontier_guidance(ExecutionState& state) {
    // Get current program state
    auto position = extract_position(state);

    // Consult frontier
    if (frontier.contains(position)) {
        // This is a frontier position - explore deeply!
        state.priority = HIGH;
        state.exploration_budget *= 2;
    } else if (visited.contains(position)) {
        // Already explored - lower priority
        state.priority = LOW;
        state.exploration_budget /= 2;
    }
}
```

### Expected Impact
- **Before**: Random walk, revisiting same areas
- **After**: Systematic exploration, always pushing boundaries
- **Coverage speed**: 5-10x faster to reach new areas

---

## 4. Domain-Specific Input Generation

### Problem

Generic seeds like "test" and "ABCDEF" are useless for mazes that need "wsad" characters.

### Solution 1: Alphabet Detection

```python
def detect_valid_alphabet(binary_path, timeout=1000):
    """Automatically detect valid input characters"""

    valid_chars = set()

    # Test each printable ASCII character
    for c in string.printable:
        result = execute_binary(binary_path, input=c, timeout=timeout)

        # If it doesn't immediately reject, it's valid
        if "only w,s,a,d accepted" not in result.stderr:
            valid_chars.add(c)

    return valid_chars

# Initialize corpus with valid characters
valid_alphabet = detect_valid_alphabet(binary_path)
initial_seeds = [c * 5 for c in valid_alphabet]  # ["wwwww", "sssss", "aaaaa", "ddddd"]
```

### Solution 2: Smart Seed Templates

```python
# Predefined patterns for common problem types
SEED_TEMPLATES = {
    'navigation': ['w'*10, 's'*10, 'a'*10, 'd'*10, 'wsad'*5],
    'text_input': ['a'*10, 'A'*10, '123', 'test'],
    'binary_data': [b'\x00'*10, b'\xff'*10, b'AAAA'],
}

def generate_smart_seeds(binary_path):
    """Generate seeds based on binary behavior"""

    # Quick test to determine problem type
    nav_test = execute_binary(binary_path, "wasd")
    if "maze" in nav_test.stdout.lower() or "direction" in nav_test.stdout.lower():
        return SEED_TEMPLATES['navigation']

    # Fallback to generic
    return SEED_TEMPLATES['text_input']
```

### Expected Impact
- **Before**: All generated inputs invalid (contained 't', 'e', 'A', 'B', etc.)
- **After**: All inputs use valid alphabet from start
- **Efficiency**: 10-20x fewer wasted executions

---

## 5. Success-Oriented Heuristics

### Detection of Progress Indicators

```python
def extract_progress_signals(output):
    """Detect signals that indicate progress toward goal"""

    signals = {
        'win_condition': 'You win' in output,
        'distance_to_goal': extract_distance_to_goal(output),
        'new_area': contains_unexplored_markers(output),
        'complexity': len(output),  # More output = more progress
    }

    return signals

def prioritize_inputs(corpus):
    """Sort inputs by how close they got to winning"""

    scored = []
    for input_file in corpus:
        result = execute(input_file)
        signals = extract_progress_signals(result.output)

        # Scoring function
        score = 0
        if signals['win_condition']:
            score += 1000
        score += (100 - signals['distance_to_goal']) * 10  # Closer = higher score
        score += signals['complexity']

        scored.append((score, input_file))

    # Return highest-scoring inputs first
    return [f for _, f in sorted(scored, reverse=True)]
```

### Distance-to-Goal Estimation

For maze problems specifically:

```python
def estimate_distance_to_goal(maze_output):
    """Calculate Manhattan distance from player to goal"""

    player_pos = find_char_position(maze_output, 'X')
    goal_pos = find_char_position(maze_output, '#')

    if player_pos and goal_pos:
        x1, y1 = player_pos
        x2, y2 = goal_pos
        return abs(x2 - x1) + abs(y2 - y1)

    return float('inf')
```

### Expected Impact
- **Before**: No understanding of which inputs are "close" to winning
- **After**: Focus exploration on promising paths
- **Success rate**: 10-100x improvement for goal-oriented problems

---

## 6. Parallel Deep Path Exploration

### Strategy

Instead of exploring many shallow paths, explore fewer paths very deeply in parallel.

```python
def parallel_deep_exploration(binary_path, num_workers=8):
    """Run multiple deep explorations in parallel"""

    # Generate diverse starting points
    seeds = generate_diverse_seeds(count=num_workers)

    with multiprocessing.Pool(num_workers) as pool:
        # Each worker explores ONE path deeply
        results = pool.map(
            lambda seed: explore_single_path_deeply(
                binary_path,
                seed,
                max_depth=50,
                exploration_budget=10000
            ),
            seeds
        )

    # Collect all discovered paths
    return merge_results(results)

def explore_single_path_deeply(binary_path, seed, max_depth, exploration_budget):
    """Take one seed and extend it as far as possible"""

    current_input = seed
    best_score = -1

    for depth in range(max_depth):
        # Try extending with each possible character
        candidates = [current_input + c for c in ['w', 's', 'a', 'd']]

        # Execute all candidates
        results = [(c, execute_and_score(c)) for c in candidates]

        # Take the best one
        best_candidate, best_result = max(results, key=lambda x: x[1].score)

        if best_result.score > best_score:
            current_input = best_candidate
            best_score = best_result.score
        else:
            # Dead end, try random exploration
            current_input = best_candidate

    return current_input
```

### Expected Impact
- **Before**: Sequential exploration, limited depth
- **After**: 8x parallelism, each path reaches deeper
- **Speed**: 8x faster to find deep bugs

---

## 7. Incremental Path Extension

### Current Behavior

```
Seed "test" → Generate 4 variants → Execute all → Next round
```

### Proposed Behavior

```
Seed "test" → Generate 1 promising variant → Execute →
  If good: Extend further → Execute → If good: Continue...
  If bad: Try different variant
```

### Implementation

```python
def incremental_extension(seed_input, binary_path, target_depth=30):
    """Incrementally extend one input until target depth"""

    current = seed_input

    for step in range(target_depth):
        # Try each direction
        candidates = {
            'w': current + 'w',
            's': current + 's',
            'a': current + 'a',
            'd': current + 'd',
        }

        # Execute and evaluate
        results = {}
        for direction, test_input in candidates.items():
            result = execute_symbolic(binary_path, test_input)
            results[direction] = {
                'input': test_input,
                'coverage': result.edges_hit,
                'state': extract_state(result.output),
                'valid': 'You lose' not in result.stderr
            }

        # Choose best direction
        # Priority: valid > new state > new coverage
        best = None
        for direction, result in results.items():
            if not result['valid']:
                continue
            if result['state'] not in visited_states:
                best = result
                break
            if best is None or result['coverage'] > best['coverage']:
                best = result

        if best is None:
            # Dead end
            break

        # Extend with best choice
        current = best['input']
        visited_states.add(best['state'])

    return current
```

### Expected Impact
- **Before**: Generates short inputs, explores breadth
- **After**: Generates long inputs, explores depth
- **Solution finding**: 100x more likely to find 20+ move solutions

---

## 8. Configuration Presets

### Implementation

Add preset configurations for different problem types:

```python
# In MCP server configuration
PRESETS = {
    'maze': {
        'max_input_length': 50,
        'timeout_per_execution': 5000,
        'exploration_strategy': 'depth_first',
        'prioritize_new_states': True,
        'alphabet': 'wsad',
        'seed_templates': ['w'*10, 's'*10, 'wsad'*5],
    },

    'fuzzing': {
        'max_input_length': 1000,
        'timeout_per_execution': 100,
        'exploration_strategy': 'breadth_first',
        'prioritize_coverage': True,
        'alphabet': None,  # All bytes
        'seed_templates': None,
    },

    'format_string': {
        'max_input_length': 100,
        'timeout_per_execution': 500,
        'exploration_strategy': 'mutation',
        'alphabet': string.printable,
        'seed_templates': ['%s', '%x', '%n'],
    }
}

# Usage in MCP tool
def run_campaign(binary_path, corpus_dir, preset='default', **overrides):
    """Run campaign with optional preset"""

    config = PRESETS.get(preset, {}).copy()
    config.update(overrides)

    return execute_campaign(binary_path, corpus_dir, config)
```

### Expected Impact
- **Before**: User must manually tune parameters for each problem type
- **After**: One-command optimization for common scenarios
- **Usability**: 10x easier to get good results

---

## Priority Ranking

Based on impact vs. implementation effort:

| Priority | Improvement | Impact | Effort | Ratio |
|----------|-------------|--------|--------|-------|
| 1 | Deep Exploration Mode | High | Medium | 3:1 |
| 2 | Smart Seed Templates | High | Low | 5:1 |
| 3 | Incremental Extension | High | Medium | 3:1 |
| 4 | State-Based Coverage | Medium | Medium | 2:1 |
| 5 | Configuration Presets | Medium | Low | 4:1 |
| 6 | Frontier-Guided | Medium | High | 1:1 |
| 7 | Parallel Exploration | Low | High | 0.5:1 |
| 8 | Success Heuristics | Low | Medium | 0.8:1 |

## Recommended Implementation Order

### Phase 1 (Quick Wins)
1. **Smart Seed Templates** - Easy to implement, immediate improvement
2. **Configuration Presets** - Makes tool more user-friendly
3. **Deep Exploration Mode** - Core improvement for maze-like problems

### Phase 2 (Core Improvements)
4. **State-Based Coverage** - Fundamental enhancement
5. **Incremental Extension** - Better path building
6. **Frontier-Guided Exploration** - Smarter search strategy

### Phase 3 (Advanced Features)
7. **Success-Oriented Heuristics** - Domain-specific optimization
8. **Parallel Deep Exploration** - Performance scaling

## Testing Plan

Create a benchmark suite of maze problems:

```bash
benchmarks/
├── simple_maze_4x4.c      # 8 moves to solve
├── medium_maze_6x6.c      # 16 moves to solve
├── complex_maze_8x8.c     # 24 moves to solve
├── large_maze_16x16.c     # 50+ moves to solve
└── maze_with_keys.c       # Requires state tracking
```

**Success criteria:**
- Simple: 100% solve rate (current: 0%)
- Medium: 90% solve rate (current: 0%)
- Complex: 70% solve rate (current: 0%)
- Large: 30% solve rate (current: 0%)

## Conclusion

With these improvements, SymFit would be significantly more effective at:
- Deep path exploration (20-50+ moves)
- State-based problems (mazes, games, protocols)
- Goal-oriented challenges (reaching specific conditions)

The key insight: **Traditional edge coverage is insufficient for stateful, deep-path problems. We need state-aware, depth-prioritized exploration strategies.**

---

**Estimated Development Time:**
- Phase 1: 2-3 weeks
- Phase 2: 4-6 weeks
- Phase 3: 4-6 weeks
- **Total: 10-15 weeks** for full implementation

**Expected Improvement on Maze Problem:**
- Current: 0% success rate, 0.02% coverage
- After Phase 1: ~30% success rate, ~5% coverage
- After Phase 2: ~70% success rate, ~20% coverage
- After Phase 3: ~90% success rate, ~40% coverage
