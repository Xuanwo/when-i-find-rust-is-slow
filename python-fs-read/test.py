#!/usr/bin/env python3
with open("/tmp/file", "rb") as fp:
    result = fp.read()
assert len(result) == 64 * 1024 * 1024
