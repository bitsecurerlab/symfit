# SymFit Docker Development Guide

## Quick Start

### Build and Run Development Container

```bash
# Build the development image
docker-compose build symfit-dev

# Start interactive development shell
docker-compose run --rm symfit-dev
```

### Inside the Container

```bash
# You're now in: /workspace as user 'dev'

# 1. Configure SymFit
./configure --target-list=x86_64-linux-user --enable-debug

# 2. Build with plugin system
make -j$(nproc)

# 3. Test the build
ls -la x86_64-linux-user/qemu-x86_64
ls -la plugin-system/symfit_plugin.o

# 4. Test with maze binary (mounted from /tmp)
echo "test" | ./x86_64-linux-user/qemu-x86_64 --plugin test.js /tmp/maze_test/maze-nosleep
```

## Development Workflow

### Option 1: Interactive Development (Recommended)

```bash
# Start container
docker-compose run --rm symfit-dev

# Inside container: configure and build
./configure --target-list=x86_64-linux-user --enable-debug
make -j$(nproc)

# Make code changes on host (files are mounted)
# Then rebuild in container
make -j$(nproc)

# Exit container when done
exit
```

### Option 2: One-off Commands

```bash
# Configure
docker-compose run --rm symfit-dev ./configure --target-list=x86_64-linux-user

# Build
docker-compose run --rm symfit-dev make -j$(nproc)

# Run tests
docker-compose run --rm symfit-dev make test
```

### Option 3: Keep Container Running

```bash
# Start container in background
docker-compose up -d symfit-dev

# Execute commands
docker-compose exec symfit-dev ./configure --target-list=x86_64-linux-user
docker-compose exec symfit-dev make -j$(nproc)

# Stop when done
docker-compose down
```

## Features

### ✅ Pre-installed Dependencies

- Ubuntu 20.04 base
- All QEMU/SymFit build dependencies
- QuickJS (built automatically)
- Z3 solver
- Clang 12 toolchain
- Python 3 with required packages

### ✅ Persistent Volumes

- `symfit-build`: Build artifacts persist between runs
- `symfit-ccache`: Compilation cache for faster rebuilds
- Source files: Live-mounted from host

### ✅ Development Features

- Live source editing on host
- Fast incremental builds (ccache)
- Access to /tmp for test binaries
- Non-root user (dev)

## Verify Plugin System Integration

```bash
# Inside container

# 1. Check QuickJS built
ls -la external/quickjs/libquickjs.a

# 2. Check plugin files
ls -la plugin-system/

# 3. Configure SymFit
./configure --target-list=x86_64-linux-user --enable-debug 2>&1 | tee config.log

# 4. Build
make -j$(nproc) 2>&1 | tee build.log

# 5. Verify plugin system compiled
ls -la plugin-system/symfit_plugin.o

# 6. Check binary has plugin symbols
nm x86_64-linux-user/qemu-x86_64 | grep -i plugin
```

## Common Commands

### Build Commands

```bash
# Clean build
make clean
./configure --target-list=x86_64-linux-user --enable-debug
make -j$(nproc)

# Incremental build (after changes)
make -j$(nproc)

# Build only plugin system
make plugin-system/symfit_plugin.o

# Rebuild specific component
rm x86_64-linux-user/qemu-x86_64
make x86_64-linux-user/qemu-x86_64
```

### Testing Commands

```bash
# Test prototype (already built)
cd plugins-prototype
make
./test/test_plugin --plugin examples/simple_plugin.js --moves "dddddsssss"

# Once Phase 2 is complete, test with real binary
./x86_64-linux-user/qemu-x86_64 --plugin maze_plugin.js /tmp/maze_test/maze-nosleep
```

### Debugging

```bash
# View configuration
cat config-host.mak | grep -i quickjs

# Check compilation errors
make plugin-system/symfit_plugin.o V=1

# Verbose build
make V=1

# Check dependencies
ldd x86_64-linux-user/qemu-x86_64
```

## Troubleshooting

### QuickJS not built

```bash
cd external/quickjs
make -j$(nproc)
cd ../..
make clean && make -j$(nproc)
```

### Configuration fails

```bash
# Check error
./configure --target-list=x86_64-linux-user 2>&1 | grep -i error

# All dependencies should be pre-installed in container
# If something is missing, update Dockerfile.dev
```

### Build fails

```bash
# Clean build
make clean
./configure --target-list=x86_64-linux-user --enable-debug
make -j$(nproc) V=1  # Verbose output
```

### Container won't start

```bash
# Rebuild from scratch
docker-compose build --no-cache symfit-dev
docker-compose run --rm symfit-dev
```

## File Organization

### In Container

```
/workspace/                    (your source, mounted from host)
├── plugin-system/            Plugin system source
│   ├── symfit_plugin.h
│   ├── symfit_plugin.c
│   └── Makefile.objs
├── external/quickjs/         QuickJS (built during image creation)
│   └── libquickjs.a
├── plugins-prototype/        Working prototype
├── build/                    Build artifacts (persistent volume)
└── ...                       Rest of SymFit source
```

### Volumes

```
symfit-build      → /workspace/build  (persistent)
symfit-ccache     → /home/dev/.ccache (persistent)
```

## Next Steps

### After Container is Running

1. **Complete Phase 1**
   ```bash
   ./configure --target-list=x86_64-linux-user --enable-debug
   make -j$(nproc)
   ```

2. **Verify Plugin System**
   ```bash
   ls -la plugin-system/symfit_plugin.o
   nm x86_64-linux-user/qemu-x86_64 | grep -i plugin
   ```

3. **Begin Phase 2** (QEMU Hooks)
   - Follow `PLUGIN_INTEGRATION_GUIDE.md` - Phase 2
   - Add memory write hooks
   - Add syscall hooks

4. **Test with Maze**
   - After Phase 2 complete
   - Run real maze binary with plugin

## Production Build

To build the full production image:

```bash
docker-compose build symfit-prod
docker-compose run --rm symfit-prod
```

This builds everything (SymCC, SymSan, SymFit) in the image.

---

**Ready to start?**

```bash
docker-compose build symfit-dev
docker-compose run --rm symfit-dev
```

Then inside:

```bash
./configure --target-list=x86_64-linux-user --enable-debug
make -j$(nproc)
```
