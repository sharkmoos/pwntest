#!/usr/bin/env bash

# It seems to skip the files if we don't delete them
#rm build_docs/source/binary.rst
#rm build_docs/source/web.rst
#rm build_docs/source/extended_gdb.rst
#rm build_docs/source/pwntest.rst

#rm build_docs/source/pwntest.rst
rm -rf docs/*
rm build_docs/source/pwntest.modules.rst

# Why is there no recursive option?
sphinx-apidoc -F -e -o build_docs/source pwntest/
#sphinx-apidoc -e -o build_docs/source pwntest/modules/

cd build_docs || exit 1
make html
cd ..
cp -R build_docs/build/html/* docs/
