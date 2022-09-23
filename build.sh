#!/usr/bin/env bash
set -eu

cd $(dirname ${0})

for each in `ls cmd` ; do
    go build -o "bin/${each}" "./cmd/${each}"
done
