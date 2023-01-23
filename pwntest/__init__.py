"""
Perhaps could use "isinstance" to check if the object has been initialised in the call function,
and if not initialise it.
"""
import os
import pwn

from pwntest.modules.pwn_ops import PwnAutomation
from pwntest.modules.web_ops import WebAutomation

from pwntest.modules.general import SSHTest, connect_ssh, run_socket_listener


class PwnTest:
    def __init__(self, binary_path: str = "", ip: str = "", port: int = 0, ssh=None) -> None:
        self.remote_ip: str = ip
        self.remote_port: int = port
        self.binary_path: str = binary_path
        self.remote_test: bool = False
        self.local_test: bool = False
        self.SSHTest = None

        # TODO: Update this to something more elegant,
        #       where these are only initialised the first time they're used
        self.PwnAutomation = PwnAutomation(binary_path=binary_path, ip=ip, port=port, ssh=ssh)
        self.WebAutomation = WebAutomation(rhost=ip, rport=port, lhost="127.0.0.1", lport=1337)

        if ssh:
            self.ssh_tests = SSHTest(binary_path=binary_path, ip=ip, port=port, ssh=ssh)
            if "user" not in ssh:
                raise ValueError("SSH User not provided")
            if "port" not in ssh:
                ssh["port"] = 22
            if "password" not in ssh and "keyfile" not in ssh:
                raise ValueError("SSH Password or Keyfile not provided")

        if binary_path:
            if not os.path.isfile(binary_path):
                raise FileNotFoundError("Local binary target found")
            self.elf = pwn.context.binary = pwn.ELF(self.binary_path, checksec=False)

    def assert_priv_esc(self, user: str, exploit) -> bool:
        """
        user: the user that the exploit should escalate to
        exploit: a python function that returns a bash/sh pwntools pwn.tubes[process|ssh|sock] object
        """
        tube = exploit(self.remote_ip, self.remote_port)
        tube.clean()
        tube.sendline("whoami")
        output = tube.clean(timeout=1)
        if user.encode() in output:
            return True
        else:
            return False
