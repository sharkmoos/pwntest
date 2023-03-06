#!/usr/bin/env bash

# It seems to skip the files if we don't delete them
rm docs/source/binary.rst
rm docs/source/web.rst
rm docs/source/extended_gdb.rst
rm docs/source/pwntest.rst

# Why is there no recursive option?
sphinx-apidoc -o docs/source pwntest/
sphinx-apidoc -o docs/source pwntest/modules/

# this is the same as pwntools, so no need to document it
rm docs/source/gdb_api_bridge.rst

cd docs || exit 1
make html
