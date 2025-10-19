#!/bin/sh

if [ ! -d obj ]; then
    mkdir obj
fi

cd obj
env MAKEOBJDIR=$(realpath .) make -C .. "$@"
