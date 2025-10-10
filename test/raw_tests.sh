#!/bin/env bash

./build/pliney -type dgram  \!\> body ./test/data/dns_cnn =\> target 8.8.8.8 53  =\> raw  -mode overwrite ${RUNNER_TEMP}/testing.raw

diff test/data/dns_cnn ${RUNNER_TEMP}/testing.raw