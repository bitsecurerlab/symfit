#!/bin/bash
compile_symcc=0
compile_symsan=0
compile_symfit_symcc=0
compile_symfit_symsan=0
debug=0
for arg in "$@"
do
  case $arg in 
    --symcc)
    compile_symcc=1
    shift
    ;;
    --symsan)
    compile_symsan=1
    shift
    ;;
    --symfit_symcc)
    compile_symfit_symcc=1
    shift
    ;;
    --symfit_symsan)
    compile_symfit_symsan=1
    shift
    ;;
    --enable_debug)
    debug=1
    shift
    ;;
    --disable_debug)
    debug=0
    shift
    ;;
  esac
done

evaluation="$PWD"

if [ $compile_symcc == 1 ]
  then
    build="/workdir/symcc_build"
    source="/workdir/symcc"
    fuzz_helper="util/symcc_fuzzing_helper"
    cd $build
    cmake -G Ninja                      \
      -DQSYM_BACKEND=ON                 \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DZ3_TRUST_SYSTEM_VERSION=on      \
      ${source}
      # exit if command failed
      if [ $? -ne 0 ]; then
        echo "cmake failed"
        exit 1
      fi
      ninja all
      if [ $? -ne 0 ]; then
        echo "ninja all failed"
        exit 1
      fi
      # cargo install --path "$source/$fuzz_helper"
fi

if [ $compile_symsan == 1 ]
  then
    ln -s /usr/bin/python2 /usr/bin/python
    build="/workdir/symsan_build"
    source="/workdir/symsan"
    cd $build
    CC=clang-12 CXX=clang++-12            \
    cmake -DCMAKE_BUILD_TYPE=Release      \
          -DCMAKE_INSTALL_PREFIX=${build} \
          ${source}
    make -j && make install
fi

if [ $compile_symfit_symcc == 1 ]
  then
    build="/workdir/symfit_symcc_build"
    source="/workdir/symfit"
    cd $build
    if [ $debug == 1 ]; then
      ${source}/configure                \
      --audio-drv-list=                  \
        --disable-bluez                  \
        --disable-sdl                    \
        --disable-gtk                    \
        --enable-2nd-ccache              \
        --enable-debug                   \
        --disable-vte                    \
        --disable-opengl                 \
        --disable-virglrenderer          \
        --target-list=x86_64-linux-user  \
        --enable-capstone=git            \
        --symcc-source=/workdir/symcc    \
        --symcc-build=/workdir/symcc_build       \
        --symsan-source=/workdir/symsan  \
        --symsan-build=/workdir/symsan_build    \
      && make -j
    else
      ${source}/configure                \
      --audio-drv-list=                  \
        --disable-bluez                  \
        --disable-sdl                    \
        --disable-gtk                    \
        --enable-2nd-ccache              \
        --disable-vte                    \
        --disable-opengl                 \
        --disable-virglrenderer          \
        --target-list=x86_64-linux-user  \
        --enable-capstone=git            \
        --symcc-source=/workdir/symcc    \
        --symcc-build=/workdir/symcc_build       \
        --symsan-source=/workdir/symsan  \
        --symsan-build=/workdir/symsan_build    \
      && make -j
    fi
fi

if [ $compile_symfit_symsan == 1 ]
  then
    build="/workdir/symfit_symsan_build"
    source="/workdir/symfit"
    cd $build
    if [ $debug == 1 ]; then
      ${source}/configure                \
      --audio-drv-list=                  \
        --disable-bluez                  \
        --disable-sdl                    \
        --disable-gtk                    \
        --enable-2nd-ccache              \
        --enable-debug                   \
        --disable-vte                    \
        --disable-opengl                 \
        --disable-virglrenderer          \
        --target-list=x86_64-linux-user  \
        --enable-capstone=git            \
        --symcc-source=/workdir/symcc    \
        --symcc-build=/workdir/symcc_build       \
        --symsan-source=/workdir/symsan  \
        --symsan-build=/workdir/symsan_build    \
      && make -j
    else
      ${source}/configure                \
      --audio-drv-list=                  \
        --disable-bluez                  \
        --disable-sdl                    \
        --disable-gtk                    \
        --enable-2nd-ccache              \
        --disable-vte                    \
        --disable-opengl                 \
        --disable-virglrenderer          \
        --target-list=x86_64-linux-user  \
        --enable-capstone=git            \
        --symcc-source=/workdir/symcc    \
        --symcc-build=/workdir/symcc_build       \
        --symsan-source=/workdir/symsan  \
        --symsan-build=/workdir/symsan_build    \
      && make -j
    fi
fi