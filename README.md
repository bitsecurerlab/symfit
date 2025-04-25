``` shell
$ git clone https://github.com/bitsecurerlab/symsan.git
$ ln -s /usr/bin/python2 /usr/bin/python
$ cd ${/path/to/build}
$ CC=clang-12 CXX=clang++-12            \
$ cmake -DCMAKE_BUILD_TYPE=Release      \
$       -DCMAKE_INSTALL_PREFIX=${/path/to/build} \
$       ${/path/to/symsan}
$ make -j && make install
```

### To download symcc:

`$ git clone https://github.com/bitsecurerlab/symcc.git`

``` shell
$ ../configure                                                    \
      --audio-drv-list=                                           \
      --disable-bluez                                             \
      --disable-sdl                                               \
      --disable-gtk                                               \
      --disable-vte                                               \
      --disable-opengl                                            \
      --disable-virglrenderer                                     \
      --disable-werror                                            \
      --target-list=x86_64-linux-user                             \
      --enable-capstone=git                                       \
      --symsan-source=/workdir/symsan                             \
      --symsan-build=/workdir/symsan_build                        \
      --symcc-source=/path/to/symcc/sources                       \
      --symcc-build=/path/to/symcc/build
$ make -j
```

## Docker Build Instructions

To build the Docker image for this project, run the following command from the project root (where the `Dockerfile` is located):

```sh
docker build -t symfit_env .
```

This will create a Docker image named `symfit_env`.

## Running Scripts in the `run` Directory

The `run` directory contains scripts for building and launching the environment:

### 1. `./launch.sh`

This script launches a Docker container from the built image and mounts the necessary directories. It is configured to use the `symfit_env` image by default:

```sh
./launch.sh
```

This will start an interactive shell inside the container with the project and relevant data directories mounted, then run the compile script within the container.

### 2. `./compile.sh`

Inside the container, this script is used to build various components. It accepts several options:

- `--symcc`        : Compile symcc
- `--symsan`       : Compile symsan
- `--symfit_symcc` : Compile symfit with symcc backend
- `--symfit_symsan`: Compile symfit with symsan backend

Example usage:

```sh
./compile.sh --symfit_symcc
```

You can combine multiple options as needed.

```sh
./compile.sh --symcc --symfit_symcc
```