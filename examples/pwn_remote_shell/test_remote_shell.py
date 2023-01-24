import sys
import unittest

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
from examples.pwn_remote_shell.exploit import main as exploit_code
import pwntest

tester = pwntest.PwnTest(ip="127.0.0.1", port=9002)


def test_remote_shell():
    assert tester.PwnAutomation.assert_remote_exploit(exploit_code, shell=False) is True


def test_remote_user():
    assert tester.assert_priv_esc(user="ctf", exploit=exploit_code, remote_exploit=True) is True

test_remote_shell()
test_remote_user()