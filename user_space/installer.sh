#!/bin/bash


cd source_files

echo [1] compiling the source files
echo -- gcc kfw_user.c kfw_user_functions.c -o kfw --

gcc kfw_user.c kfw_user_functions.c -o kfw

mv ./kfw ../

echo [3] compilation successfull
