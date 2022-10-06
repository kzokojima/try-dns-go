#!/usr/bin/env bash
set -eu -o pipefail

cd $(dirname ${0})

trap 'handle_error $LINENO' ERR

handle_error() {
    echo "ERROR: \$LINENO = $1, \$? = $?" >&2
    docker compose down 2> /dev/null
}

assert_equals() {
    diff --ignore-space-change <(echo "$1") <(echo "$2")
}

test_go() {
    if ! go test; then
        status=1
    fi
    for each in `ls cmd` ; do
        if ! go test "./cmd/${each}"; then
            status=1
        fi        
    done
}

test_sh() {
    export COMPOSE_PROJECT_NAME="$(basename $(pwd))-testing"
    export DNS_PORT=8153
    readonly CMD="bin/lookup @127.0.0.1 -p ${DNS_PORT}"

    docker compose up -d 2> /dev/null

    ./build.sh

    for each in test/*.sh ; do
        if source $each; then
            echo -e "ok\t$each"
        else
            echo -e "FAIL\t$each"
            status=1
        fi        
    done

    docker compose down 2> /dev/null
}

status=0
test_go
test_sh
if [[ $status = 0 ]]; then
    echo OK
else
    echo FAIL
fi
exit $status
