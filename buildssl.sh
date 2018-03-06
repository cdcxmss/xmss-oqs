#!/bin/bash
make clean
./config -debug -g -ldl -fPIC -DPURIFY
make depend
make -j4
#make clean
