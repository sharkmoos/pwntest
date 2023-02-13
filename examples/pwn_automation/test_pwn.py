import sys
import unittest
from exploit import get_flag as exploit_flag  
from exploit import get_shell as exploit_shell

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

tester = pwntest.PwnTest("127.0.0.1", 9001, binary_path="examples/pwn_remote_flag/challenge/challenge")


def test_remote_flag():
    tester.PwnAutomation.assert_exploit(exploit=exploit_flag, flag="cueh{", flag_path="/flag")


def test_remote_shell():
    assert tester.PwnAutomation.assert_exploit(exploit=exploit_shell, remote=True)

