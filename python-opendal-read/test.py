#!/usr/bin/env python3
import opendal

op = opendal.Operator("fs", root=str("/tmp"))

result = op.read("file")
assert len(result) == 64 * 1024 * 1024
