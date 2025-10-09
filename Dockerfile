# ---- Base OS ---------------------------------------------------------------
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ARG TZ=Etc/UTC
ARG CLANG_VER=12
ARG Z3_TAG=z3-4.8.7

# ---- OS deps (single layer, no recommends) --------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates tzdata \
      # toolchain & build
      build-essential clang-${CLANG_VER} lld-${CLANG_VER} llvm-${CLANG_VER}-dev \
      libc++-${CLANG_VER}-dev libc++abi-${CLANG_VER}-dev \
      cmake ninja-build ccache pkg-config \
      git curl wget parallel unzip zip \
      # lang & python
      python3 python3-pip python3-setuptools python2 python-is-python3 \
      # build utils
      autoconf automake libtool flex bison ragel gdb \
      # libs for qemu/symfit build
      libpixman-1-dev libglib2.0-dev zlib1g-dev libreadline-dev \
      # media/image/audio libs (as in original)
      libopenjp2-7-dev libpng-dev libcairo2-dev libtiff-dev liblcms2-dev \
      libjpeg-dev libjpeg-turbo8-dev libflac-dev libogg-dev libvorbis-dev \
      libopus-dev libmp3lame-dev libmpg123-dev libasound2-dev \
      # boost & friends
      libboost-all-dev texinfo \
      # Rust (symcc/symsan ecosystems sometimes need it)
      cargo \
    && rm -rf /var/lib/apt/lists/*

# ---- Python packages (single call) -----------------------------------------
RUN python3 -m pip install --no-cache-dir \
      lit jinja2

# ---- Z3 (pinned tag, shallow clone, install, then clean) -------------------
RUN git clone --depth 1 --branch ${Z3_TAG} https://github.com/Z3Prover/z3.git /opt/z3 && \
    cmake -S /opt/z3 -B /opt/z3/build -DZ3_BUILD_LIBZ3_SHARED=ON -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /opt/z3/build -j && \
    cmake --install /opt/z3/build && \
    ldconfig && \
    rm -rf /opt/z3

WORKDIR /workspace

# Toolchain defaults (overridable)
ENV CC=clang-${CLANG_VER} \
    CXX=clang++-${CLANG_VER} \
    PATH=/usr/lib/ccache:$PATH

# Helpful defaults for faster builds
ENV CCACHE_DIR=/home/dev/.ccache \
    CCACHE_MAXSIZE=5G

# Copy source code from host (excludes .git, build artifacts, etc. via .dockerignore)
COPY . /workspace

RUN chmod +x ./build.sh && ./build.sh all -j"$(nproc)"

# Default shell
CMD ["/bin/bash"]

