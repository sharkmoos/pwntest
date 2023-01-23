import sys
import unittest
from exploit import main as exploit_code

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

tester = pwntest.PwnTest("./pwn_remote_flag/challenge/challenge", "127.0.0.1", 4444)


def test_remote_flag():
    tester.PwnAutomation.assert_exploit(exploit=exploit_code, shell=False, flag="cueh{")


