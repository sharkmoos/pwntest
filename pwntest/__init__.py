"""
Perhaps could use "isinstance" to check if the object has been initialised in the call function,
and if not initialise it.
"""
import os
import threading

import pwnlib.context
import pwnlib.elf
import pwnlib.log
import pwnlib.replacements

import pwntest.modules.extended_gdb as extended_gdb

from pwntest.modules.pwn_ops import PwnAutomation
from pwntest.modules.web_ops import WebAutomation

from pwntest.modules.general import SSHTest, run_socket_listener

from logging import Formatter
from logging import getLogger as logging_getLogger


pwnlib.log.getLogger("pwnlib").setLevel("WARNING")


def configure_logger():
    pwnlog = logging_getLogger("pwntest")
    if not pwnlog.handlers:
        iso_8601 = '%Y-%m-%dT%H:%M:%S'
        fmt = '%(asctime)s:%(levelname)s:%(name)s:%(message)s'
        log_file = pwnlib.log.LogfileHandler()
        log_file.setFormatter(Formatter(fmt, iso_8601))

        formatter = pwnlib.log.Formatter()
        console = pwnlib.log.Handler()
        console.setFormatter(formatter)

        pwnlog.addHandler(console)
        pwnlog.addHandler(log_file)


class PwnTest:
    def __init__(self, ip: str = "", port: int = 0, binary_path="", ssh=None) -> None:
        self.remote_ip: str = ip
        self.remote_port: int = port
        self.binary_path: str = binary_path
        self.remote_test: bool = False
        self.local_test: bool = False

        configure_logger()
        self.log = pwnlib.log.getLogger("pwntest")
        self.log.setLevel("DEBUG")

        # TODO: Update this to something more elegant,
        #       where these are only initialised the first time they're used
        self.PwnAutomation = PwnAutomation(binary_path=binary_path, ip=ip, port=port, ssh=ssh)
        self.WebAutomation = WebAutomation(rhost=ip, rport=port, lhost="127.0.0.1", lport=1337)
        # self.SSHTest = SSHTest(binary_path=binary_path, ip=ip, port=port, ssh=ssh)

        if ssh:
            if "user" not in ssh:
                raise ValueError("SSH User not provided")
            if "port" not in ssh:
                ssh["port"] = 22
            if "password" not in ssh and "keyfile" not in ssh:
                raise ValueError("SSH Password or Keyfile not provided")

            self.SSHTest = SSHTest(binary_path="", ip=ip, port=port, ssh=ssh)

        # if binary_path:
        #     if not os.path.isfile(binary_path):
        #         raise FileNotFoundError("Local binary target found")

    def assert_priv_esc(self, user: str, exploit, remote_exploit=False) -> bool:
        """
        user: the user that the exploit should escalate to
        exploit: a python function that returns a bash/sh pwntools pwn.tubes.[process|ssh|sock] object
        """
        if remote_exploit:
            tube = exploit(self.remote_ip, self.remote_port)
        else:
            tube = exploit()
        tube.sendline(b"id")
        output = tube.recvline_contains(b"(", timeout=1)
        if user.encode() in output:
            ret = True
        else:
            ret = False
        tube.close()
        return ret

    def run_reverse_shell_exploit(self, local_host, local_port, exploit_function) -> pwnlib.tubes.listen.listen or None:
        if not exploit_function:
            raise ValueError("Exploit function not provided")
        socket_details: dict = {}

        # create a listener and run it in a new thread
        listener_thread = threading.Thread(target=run_socket_listener, args=(local_host, local_port, socket_details))
        listener_thread.start()

        # create thread to run the exploit function
        exploit_thread = threading.Thread(target=exploit_function, args=(self.remote_ip, self.remote_port, local_host, local_port))
        exploit_thread.start()
        pwnlib.replacements.sleep(1)

        listener_thread.join()  # wait for the listener to finish or timeout
        if socket_details:  # if there are details, a connection was made
            conn = pwnlib.tubes.remote.remote(
                socket_details["host"],
                socket_details["port"],
                fam=socket_details["fam"],
                typ=socket_details["type"],
                sock=socket_details["conn"]
            )
            self.log.success("Upgraded to full pwntools connection")
        else:
            self.log.warning("Could not establish a connection to the remote host")
            conn = None

        return conn

