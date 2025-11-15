#!/bin/env bash

# Should result in a response of HTTP/1.1 301 Moved Permanently.
./build/pliney \!\> transport tcp =\> body ./test/data/http_get =\> target www.cnn.com 80
