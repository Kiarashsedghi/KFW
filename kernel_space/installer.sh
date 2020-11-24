#!/bin/bash

echo [1] copying header files ...

cp ./header_files/* /usr/src/linux-headers-$(uname -r)/include/linux

echo [2] header files copied successfully

cd source_files

echo [3] making the module

cd modules

echo [4] installing kernel module

insmod cdd107.ko

echo [5] kernel module installed successfully