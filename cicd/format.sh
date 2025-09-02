#!/bin/env bash

# TODO: Error checking

check_command=""
if [ $1 = "format" ]; then
	echo "Formatting in place ..."
	check_command="-i"
else
	echo "Checking only ..."
	check_command="--dry-run -Werror"
fi

clang-format-18 --verbose ${check_command} --files=$2
