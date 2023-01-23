import sys
import unittest
from exploit import main as exploit_code

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

tester = pwntest.PwnTest("./pwn_remote_flag/challenge/challenge", "127.0.0.1", 4444)


def test_remote_shell():
    assert tester.PwnAutomation.assert_exploit(exploit_code, shell=True)


def test_remote_user(self):
    self.assert_priv_esc(tester.PwnAutomation.assert_exploit("ctf", exploit_code))