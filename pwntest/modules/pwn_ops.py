import unittest
import os
import pwn
import sys

from pwntest.modules.general import SSHTest, connect_ssh
# from pwntest.modules.base import PwnTestBase


# class PwnAutomation(PwnTestBase):
class PwnAutomation:
    def __init__(self, binary_path: str = "", ip: str = "", port: int = 0, ssh=None) -> None:
        self.remote_ip: str = ip
        self.remote_port: int = port
        self.binary_path: str = binary_path
        self.ssh: pwn.ssh
        self.remote_test: bool = False
        self.local_test: bool = False

        if ip and not ssh:
            self.remote_test = True
            self.remote = pwn.remote(ip, port)
        if ssh:
            self.ssh_test = True
            if "user" not in ssh:
                raise ValueError("SSH User not provided")
            if "port" not in ssh:
                ssh["port"] = 22
            if "password" not in ssh and "keyfile" not in ssh:
                raise ValueError("SSH Password or Keyfile not provided")
            elif "password" in ssh:
                # TODO: Switch connect_ssh with a true/false check rather than open connection
                self.ssh = connect_ssh(ip=self.remote_ip, port=self.remote_port, user=self.ssh["user"], password=self.ssh["password"])
            elif "keyfile" in ssh:
                # TODO: Switch connect_ssh with a true/false check rather than open connection
                self.ssh = connect_ssh(ip=self.remote_ip, port=self.remote_port, user=self.ssh["user"], keyfile=self.ssh["keyfile"])
        if binary_path:
            self.local_test = True
            if not os.path.isfile(binary_path):
                raise FileNotFoundError("Local binary target found")
            self.elf = pwn.context.binary = pwn.ELF(self.binary_path, checksec=False)

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
            process: pwn.tubes.process = exploit(remote)
            process.clean()
            process.sendline("echo test_string")
            output = process.clean(timeout=1)
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

    def assert_priv_esc(self, user: str, exploit) -> bool:
        """
        user: the user that the exploit should escalate to
        exploit: a python function that returns a bash/sh pwntools pwn.tubes[process|ssh|sock] object
        """
        tube = exploit()
        tube.clean()
        tube.sendline("whoami")
        output = tube.clean(timeout=1)
        if user.encode() in output:
            return True
        else:
            return False


