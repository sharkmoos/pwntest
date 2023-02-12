import sys
import pytest
import os

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

from examples.web_login.exploit import main as exploit_code

rhost, rport = "127.0.0.1", 9004
lhost, lport = "127.0.0.1", 4444

tester = pwntest.PwnTest(ip=rhost, port=rport)


def test_reverse_shell():
    shell = tester.run_reverse_shell_exploit(lhost, lport, exploit_code)
    if not shell:
        pytest.fail("Failed to get reverse shell")
        exit()
    shell.sendline(b"echo FOOBAR")
    assert shell.recvline().strip() == b"FOOBAR"
    shell.close()
