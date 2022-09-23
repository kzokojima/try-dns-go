#!/usr/bin/env bash
set -eu -o pipefail

cd $(dirname ${0})

trap 'handle_error $LINENO' ERR

handle_error() {
    echo "ERROR: \$LINENO = $1, \$? = $?" >&2
    docker compose down 2> /dev/null
}

assert_equals() {
    if [[ "${1}" != "${2}" ]] ; then
        {
            echo 'failed'
            echo 'expected:'
            echo '```'
            echo "${1}"
            echo '```'
            echo 'actual:'
            echo '```'
            echo "${2}"
            echo '```'
        } >&2
        docker compose down 2> /dev/null
        exit 1
    fi
}

export COMPOSE_PROJECT_NAME="$(basename $(pwd))-testing"
export DNS_PORT=8153
readonly CMD="bin/lookup @127.0.0.1 -p ${DNS_PORT}"

docker compose up -d 2> /dev/null

./build.sh

for each in test/*.sh ; do
    . $each
done

docker compose down 2> /dev/null

echo OK
