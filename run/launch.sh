#!/bin/bash
# lightweight env for running symfit
# map local folders and compile
DKIMG="symfit_env" 

docker run --rm -ti --ulimit core=0 \
            -v $PWD:/workdir        \
            $DKIMG /bin/bash
