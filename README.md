
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
