#!/usr/bin/env bash

rm docs/source/binary.rst
rm docs/source/web.rst
rm docs/source/extended_gdb.rst
rm docs/source/pwntest.rst

sphinx-apidoc -o docs/source pwntest/
sphinx-apidoc -o docs/source pwntest/modules/
rm docs/source/gdb_api_bridge.rst

cd docs 
make html
