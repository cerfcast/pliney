#/bin/env bash

tests="raw_tests.sh help_tests.sh lua/sanity_test.sh lua/http_tests.sh"

for i in ${tests}; do
		echo "Running tests in ${i} ..."
    ./test/${i}
    if [ $? -ne 0 ]; then
        echo "There was an error executing tests in ${i}"
        exit 1
    fi
done

exit 0
