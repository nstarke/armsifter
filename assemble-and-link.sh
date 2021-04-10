#!/bin/bash
as -o harness.o harness.S
ld harness.o -o harness -s