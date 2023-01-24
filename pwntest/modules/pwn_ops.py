import unittest
import os
import sys
import pytest

import pwnlib.log
import pwnlib.tubes

from pwntest.modules.general import SSHTest, connect_ssh
# from pwntest.modules.base import PwnTestBase


# class PwnAutomation(PwnTestBase):
class PwnAutomation:
    def __init__(self, binary_path: str = "", ip: str = "", port: int = 0, ssh=None) -> None:
        self.remote_ip: str = ip
        self.remote_port: int = port
        self.binary_path: str = binary_path
        self.remote_test: bool = False
        self.local_test: bool = False
        self.process = None

        self.log_level: str = "WARNING"
        self.log = pwnlib.log.getLogger("pwntest::PwnAutomation")

    def assert_remote_exploit(self, exploit, shell=False, flag="", flag_path="") -> bool:
        """
        exploit: a python function that either returns a shell or a flag string, as specified by
        params supplied to the function.
        shell: if True, the exploit function should return a sh/bash pwntools pwn.tubes[process|ssh|sock] object.
        flag: if shell is False, the exploit function should return a flag string.
        """

        output = exploit(self.remote_ip, self.remote_port)

        if not flag and not flag_path:
            output.sendline(b"echo FOOBAR")
            if b"FOOBAR" in output.recvline_contains(b"FOOBAR", timeout=1):
                passed = True
            else:
                passed = False

            output.close()
            return passed

        elif flag and flag_path:
            if type(output) is str:
                if flag in output:
                    return True
                else:
                    return False
            elif type(output) is bytes:
                if flag.encode() in output:
                    return True
                else:
                    return False
            else:
                return False

        else:
            raise ValueError("Must supply either (flag and flag_path) or shell")

        return output



