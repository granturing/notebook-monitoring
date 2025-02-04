#!/bin/python

import os
import subprocess

print("Unpacking code archive")
subprocess.run(["tar", "-xzf", "code.tar.gz"])

print("Starting sapp server")
subprocess.run(["sapp", "--database-name", "sapp.db", "server"])
