#!/bin/bash
as -o hello.o hello.S
ld hello.o -o hello -s