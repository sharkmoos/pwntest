import unittest
import os
import pwn
import sys
import pytest

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

    def assert_exploit(self, exploit, remote=False, shell=True, flag="", flag_path="") -> bool:
        """
        exploit: a python function that either returns a shell or a flag string, as specified by
        params supplied to the function.
        shell: if True, the exploit function should return a sh/bash pwntools pwn.tubes[process|ssh|sock] object.
        flag: if shell is False, the exploit function should return a flag string.
        """

        if shell and (not flag_path and not flag):
            command = b"echo test_string"
            expected_output = b"test_string"

        elif shell and flag_path and flag:
            self.process: pwn.tubes.process = exploit(remote)
            self.process.clean()
            self.process.sendline("echo test_string")
            output = self.process.clean(timeout=1)
            if b"test_string" in output:
                return True
            else:
                return False

        elif (shell and flag_path and not flag) or (shell and not flag_path and flag):
            raise ValueError("Flag and Flag Path must both be supplied for testing a flag read")

        elif flag:
            output = exploit()
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




