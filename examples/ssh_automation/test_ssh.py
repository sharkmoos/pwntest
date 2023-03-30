import sys
import unittest
import pwn
import pytest
import os

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

ip, port = "127.0.0.1", 9003

tester = pwntest.PwnTest(remote_target=ip, port=port, ssh={
    "user": "david",
    "password": "foobar",
    "port": port,
})


@pytest.mark.example
def test_ssh_base_user():
    assert tester.SSHAutomation.assert_current_user("david")


@pytest.mark.example
def test_ssh_priv_esc():
    with open("/tmp/priv.sh", "wt") as f:
        f.write("bash -p\n")

    assert tester.SSHAutomation.assert_current_user("david")
    assert tester.assert_priv_esc("root", "/tmp/priv.sh", tester.SSHAutomation.ssh)


test_ssh_base_user()
