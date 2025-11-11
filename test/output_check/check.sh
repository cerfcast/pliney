#!/bin/bash

for i in `ls test/output_check/input/*`; do
				grep_pattern=`cat ${i/input/output}`
				./$i 2>&1 | grep "$grep_pattern" 1>/dev/null
				if [ $? -ne 0 ]; then
								echo "For test $i, expected text not found: ${grep_pattern}"
								exit 1;
				fi
done;
