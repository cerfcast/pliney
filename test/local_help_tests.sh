#!/bin/env bash

diff test/data/help-log.txt <(./build/pliney -help)
