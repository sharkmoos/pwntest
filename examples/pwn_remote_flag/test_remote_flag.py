import sys
import unittest
from exploit import main as exploit_code  # path is from base dir (pyproject.toml)

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

tester = pwntest.PwnTest("127.0.0.1", 9001, binary_path="examples/pwn_remote_flag/challenge/challenge")


def test_remote_flag():
    tester.PwnAutomation.assert_exploit(exploit=exploit_code, shell=False, flag="cueh{", flag_path="/flag")

