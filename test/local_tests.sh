#/bin/env bash

export RUNNER_TEMP=/tmp/

tests="raw_tests.sh local_help_tests.sh log_tests.sh"

for i in ${tests}; do
    ./test/${i}
    if [ $? -ne 0 ]; then
        echo "There was an error executing tests in ${i}"
        exit 1
    fi
done

exit 0
