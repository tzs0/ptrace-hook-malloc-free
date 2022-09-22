#!/bin/sh

gcc hook.c host.c -g -O0 -w -ldl -o host
