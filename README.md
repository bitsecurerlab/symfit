# SymFit

SymFit is a symbolic execution framework for analyzing binaries, supporting multiple backends such as SymCC and SymSan. This document provides instructions for building and running SymFit using Docker.


## How to Build the Docker Image

Navigate to the root directory containing the `Dockerfile`, then build the image:

```bash
docker build -t symfit_env .
```

## Launch the Container

Enter the `run` folder and launch the container:

```bash
cd run
./launch.sh
```

## Setup SymFit Inside the Container

Once inside the container:

1. Clone the SymFit main repository:

```bash
cd /workdir
git clone https://github.com/bitsecurerlab/symfit.git
```

2. Clone the required backend repositories:

```bash
# SymCC backend
git clone https://github.com/bitsecurerlab/symcc.git

# SymSan backend
git clone https://github.com/bitsecurerlab/symsan.git
```

> If submodules are used, run:
> 
> ```bash
> git submodule update --init --recursive
> ```

3. Create the following build directories inside the workdir:

```bash
mkdir -p symcc_build symfit_symcc_build symsan_build symfit_symsan_build
```

## Compilation

Use the provided `compile.sh` script to build components.

### Usage

Compile a specific target:

```bash
./compile.sh --symfit_symcc
```

Compile multiple components:

```bash
./compile.sh --symcc --symfit_symcc
```

### Options

- `--symcc` : Compile SymCC  
- `--symsan` : Compile SymSan  
- `--symfit_symcc` : Compile SymFit with SymCC backend  
- `--symfit_symsan` : Compile SymFit with SymSan backend

> Note: If errors occur when using `--symfit_*` options, you may need to modify `compile.sh` to append the following:

```bash
--symsan-source=/workdir/symsan \
--symsan-build=/workdir/symsan_build \
--symcc-source=/workdir/symcc \
--symcc-build=/workdir/symcc_build \
```


