#/bin/env bash

export RUNNER_TEMP=/tmp/

tests=`cat test/test_names`

for i in ${tests}; do
		echo "Running tests in ${i} ..."
    ./test/${i}
    if [ $? -ne 0 ]; then
        echo "There was an error executing tests in ${i}"
        exit 1
    fi
done

./test/run_unit_tests.sh
if [ $? -ne 0]; then
	echo "Unit tests failed."
	exit 1
fi

exit 0
