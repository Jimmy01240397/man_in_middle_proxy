#!/bin/bash

dirname="$(dirname $(realpath $0))"

. $dirname/venv/bin/activate
python $dirname $@
