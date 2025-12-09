#!/bin/bash

for i in `ls test/output_check/input/*`; do
				# Make the expected output a single line but keep a copy
				# for nice printing.
				expected_output=`cat ${i/input/output}`
				grep_pattern=`cat ${i/input/output} | sed ':a;$!{N;ba};s/\n/ /g'`

				# Run the check on the oneline'd version of the actual and
				# expected output.
				actual_output=`./$i 2>&1`
				echo ${actual_output} | sed ':a;$!{N;ba};s/\n/ /g' | grep "$grep_pattern" >/dev/null 2>&1

				# Did the grep succeed or fail?
				if [ $? -ne 0 ]; then
								echo -e "For test $i, could not find\n===needle===\n${expected_output}\nin\n===haystack===\n${actual_output}"
								exit 1;
				fi
done;
