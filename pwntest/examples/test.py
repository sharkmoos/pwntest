import sys
import unittest
from pwn_remote_flag.exploit import main as exploit_code
sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")

import pwntest

tester = pwntest.pwn_ops.PwnAutomation("", "127.0.0.1", 1337)


class TestPwnRemoteFlag(unittest.TestCase):
    def test_remote_flag(self):
        self.assertTrue(
            tester.assert_exploit(exploit=exploit_code, shell=False, flag="cueh{"),
        )


class TestPwnRemoteShell(unittest.TestCase):
    def test_remote_shell(self):
        self.assertTrue(
            tester.assert_exploit(exploit_code, shell=True)
        )

    def test_remote_user(self):
        self.assert_priv_esc(
            tester.assert_exploit("ctf", exploit_code)
        )


class TestSSHPrivEsc:
    def test_ssh_priv_esc(self):
        self.assertTrue(
            tester.assert_priv_esc("root", exploit_code)
        )