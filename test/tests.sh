#/bin/env bash

tests=`test/test_names`

for i in ${tests}; do
		echo "Running tests in ${i} ..."
    ./test/${i}
    if [ $? -ne 0 ]; then
        echo "There was an error executing tests in ${i}"
        exit 1
    fi
done

exit 0
