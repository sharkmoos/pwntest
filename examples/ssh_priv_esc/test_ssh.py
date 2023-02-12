import sys
import unittest
import pwn
import pytest
import os

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

ip, port = "127.0.0.1", 9003

tester = pwntest.PwnTest(ip=ip, port=port, ssh={
        "user": "david",
        "password": "foobar",
        "port": port,
    })


def exploit_code():
    p = tester.SSHTest.ssh.run(b"bash")
    p.sendline(b"bash -p")
    return p


def test_ssh_priv_esc_local():
    assert tester.assert_priv_esc("root", exploit_code, remote_exploit=False)
    # tester.SSHTest.assert_current_user("root")


def test_ssh_base_user():
    assert tester.SSHTest.assert_current_user("david")


test_ssh_base_user()