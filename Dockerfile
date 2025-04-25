FROM ubuntu:20.04 AS base

RUN DEBIAN_FRONTEND="noninteractive" apt-get update &&\
    DEBIAN_FRONTEND="noninteractive" apt-get -yq --no-install-recommends install tcl

RUN apt-get update -y &&  \
    apt-get -y install wget python3 python3-dev python3-pip python3-setuptools apt-transport-https \
    libboost-all-dev texinfo \
    lsb-release zip llvm-dev cmake software-properties-common autoconf curl flex bison git ragel

RUN apt-get install -y cargo libpixman-1-dev g++ git ninja-build \
     python3-pip zlib1g-dev python2 pkg-config libglib2.0-dev gdb

RUN pip3 install lit
RUN pip3 install jinja2
RUN pip install jinja2

RUN apt-get install clang-12 clang++-12 libc++-12-dev libc++abi-12-dev -y

RUN apt-get install -y parallel libjpeg-turbo8

RUN git clone https://github.com/Z3Prover/z3.git /z3 && \
		cd /z3 && git checkout z3-4.8.7 && mkdir -p build && cd build && \
		cmake .. && make -j && make install
RUN ldconfig

RUN apt-get update -y && apt-get install -y libopenjp2-7-dev libpng-dev \
                        libcairo2-dev libtiff-dev liblcms2-dev libboost-dev \
                        libjpeg-dev libflac-dev libogg-dev libvorbis-dev libopus-dev \
                        libmp3lame-dev libmpg123-dev libasound2-dev \
                        liblzma-dev libjpeg-turbo8-dev \
                        libreadline-dev
WORKDIR /workdir