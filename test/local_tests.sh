#/bin/env bash

export RUNNER_TEMP=/tmp/

tests="raw_tests.sh local_help_tests.sh log_tests.sh lua/sanity_test.sh lua/http_test.sh"

for i in ${tests}; do
		echo "Running tests in ${i} ..."
    ./test/${i}
    if [ $? -ne 0 ]; then
        echo "There was an error executing tests in ${i}"
        exit 1
    fi
done

exit 0
