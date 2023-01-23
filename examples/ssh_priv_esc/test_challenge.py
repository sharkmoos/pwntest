import sys
import unittest

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

tester = pwntest.PwnTest("./pwn_remote_flag/challenge/challenge", "127.0.0.1", 4444)

class TestSSHPrivEsc(unittest.TestCase):
    def test_ssh_priv_esc(self):
        self.assertTrue(
            tester.assert_priv_esc("root", exploit_code)
        )
