#!/bin/env bash

./build/pliney -type dgram  \!\> body ./test/data/dns_cnn =\> target 8.8.8.8 53  =\> raw  -mode overwrite /tmp/testing.raw

diff test/data/dns_cnn /tmp/testing.raw