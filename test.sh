#!/usr/bin/env bash
set -eu -o errtrace -o pipefail

export COMPOSE_PROJECT_NAME="$(basename $(pwd))-testing"
export DNS_PORT=8153

cd $(dirname ${0})

trap 'handle_error $LINENO' ERR

handle_error() {
    echo "ERROR: \$LINENO = $1, \$? = $?" >&2
    set +e
    docker compose down 2> /dev/null
    pkill -f 0.0.0.0:${DNS_PORT}
    exit 1
}

assert_equals() {
    diff --ignore-blank-lines --ignore-space-change <(echo "$1") <(echo "$2")
}

test_go() {
    if ! go test; then
        status=1
        ((++fails))
    fi
    for each in `ls cmd` ; do
        if ! go test "./cmd/${each}"; then
            status=1
            ((++fails))
        fi
    done
}

test_lookup() {
    local CMD="bin/lookup @127.0.0.1 -p ${DNS_PORT}"

    docker compose up -d 2> /dev/null

    for each in test/*.sh ; do
        if source $each; then
            echo -e "ok\t${FUNCNAME[0]}\t$each"
        else
            echo -e "FAIL\t${FUNCNAME[0]}\t$each"
            status=1
            ((++fails))
        fi
    done

    docker compose down 2> /dev/null

    CMD="bin/lookup"
    for each in test/lookup/*.sh ; do
        if source $each; then
            echo -e "ok\t${FUNCNAME[0]}\t$each"
        else
            echo -e "FAIL\t${FUNCNAME[0]}\t$each"
            status=1
            ((++fails))
        fi
    done
}

test_authoritative_server() {
    local CMD="dig @127.0.0.1 -p ${DNS_PORT}"

    bin/serv -address=0.0.0.0:${DNS_PORT} -mode=authoritative -zone=testdata/zones/example.com.zone 2> /dev/null &

    # TODO: for each in test/*.sh ; do
    for each in test/*example.com*.sh ; do
        if source $each; then
            echo -e "ok\t${FUNCNAME[0]}\t$each"
        else
            echo -e "FAIL\t${FUNCNAME[0]}\t$each"
            status=1
            ((++fails))
        fi
    done

    pkill -f 0.0.0.0:${DNS_PORT}
}

test_resolver() {
    local CMD="dig @127.0.0.1 -p ${DNS_PORT}"

    bin/serv -address=0.0.0.0:${DNS_PORT} -zone=root_files/named.root -root-anchors-xml root_files/root-anchors.xml 2> /dev/null &

    for each in test/resolver/*.sh ; do
        if source $each; then
            echo -e "ok\t${FUNCNAME[0]}\t$each"
        else
            echo -e "FAIL\t${FUNCNAME[0]}\t$each"
            status=1
            ((++fails))
        fi
    done

    pkill -f 0.0.0.0:${DNS_PORT}
}

status=0
fails=0
test_go
./build.sh
test_lookup
test_authoritative_server
test_resolver
if [[ $status = 0 ]]; then
    echo OK
else
    echo FAIL "($fails)"
fi
exit $status
