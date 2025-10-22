#!/bin/env bash

diff test/data/help.txt <(./build/pliney -help)
