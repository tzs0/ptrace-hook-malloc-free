#!/bin/sh

gcc hook.c inject.c -g -O0 -w -ldl -o inject
