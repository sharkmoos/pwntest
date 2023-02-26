import os
import threading
import base64
import socket

import pwnlib.context
import pwnlib.elf
import pwnlib.log
import pwnlib.replacements
import pwnlib.filesystem

import pwntest.modules.extended_gdb as extended_gdb

from pwntest.modules.binary import PwnAutomation
from pwntest.modules.web import WebAutomation

from logging import Formatter
from logging import getLogger as logging_getLogger


class PwnTest:
    """
    PwnTest is the main class for pwntest. It initialises the other pwntest modules.
    """
    log: pwnlib.log.Logger = pwnlib.log.getLogger("pwntest")

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

        configure_logger()
        self.log.setLevel("DEBUG")
        pwnlib.log.getLogger("pwnlib").setLevel("WARNING")

        # TODO: Update this to something more elegant,
        #       where these are only initialised the first time they're used or something
        # Perhaps could use "isinstance" to check if the object has been initialised in the call function,
        # and if not initialise it.
        self.PwnAutomation: PwnAutomation = PwnAutomation(binary_path=binary_path, ip=remote_target, port=port, ssh=ssh)
        self.WebAutomation: WebAutomation = WebAutomation(rhost=remote_target, rport=port, lhost="127.0.0.1", lport=1337)
        self.SSHAutomation: SSHAutomation

        if ssh:
            self.SSHAutomation = SSHAutomation(ip=remote_target, port=port, ssh=ssh)

    def assert_priv_esc(self, user: str, priv_script: str, conn) -> bool:
        """
        Asserts that a priv esc script can be used to escalate privileges on a host. Works with most of the pwnlib tubes.
        The priv esc script must be executable on the target machine. e.g a shell script, or elf that drops a shell etc.

        :param user: The elevated user
        :param conn: A pwnlib.tubes.[process|sock|ssh] tube.
        :param priv_script: Path to the priv esc script on the local machine.
        :return: True if the priv esc script worked, False otherwise.
        """
        proc = None
        if not os.path.exists(priv_script):
            self.log.error("Priv esc file does not exist. Skipping priv esc test.")
            return False

        file_name: str = os.path.basename(priv_script)

        # don't really need to do anything for this one, but check its executable
        if isinstance(conn, pwnlib.tubes.process.process):
            if not os.access(priv_script, os.X_OK):
                self.log.error("Priv esc file is not executable")
                return False

        # upload the priv esc script to the remote host using the pwnlib.ssh module
        elif isinstance(conn, pwnlib.tubes.ssh.ssh):
            if not self.SSHAutomation.ssh:
                self.log.warning("SSH connection not established. Skipping priv esc test.")
                return False

            if not conn.connected():
                self.log.warning("SSH connection not established. Skipping priv esc test.")
                return False

            conn.upload(priv_script, f"/tmp/{file_name}")
            self.SSHAutomation.assert_file_exists(f"/tmp/{file_name}")
            proc = conn.run(b"sh")
            proc.sendline(f"chmod +x /tmp/{file_name}".encode())

        # upload the file by encoding it in base64 and decoding it on the remote host
        # TODO: Test this works for huge files
        elif isinstance(conn, pwnlib.tubes.sock.sock):
            with open(priv_script, "rb") as f:
                data = f.read()
                encoded_data = base64.b64encode(data)
                conn.sendline(b"echo -ne '" + encoded_data + f"' | base64 -d > /tmp/{file_name}".encode())
                proc = conn
                proc.sendline(f"chmod +x /tmp/{file_name}".encode())

        else:
            self.log.error("Unsupported connection type")
            return False

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

    def run_reverse_shell_exploit(self, local_host, local_port, exploit_function) -> pwnlib.tubes.listen.listen or None:
        """
        Runs an exploit function and listens for a reverse shell connection in a separate thread.

        :param local_host: The local interface to listen on
        :param local_port: The local port to listen on
        :param exploit_function: A Python function object that takes the remote host and port as arguments
        :return: A pwnlib.tubes.listen.listen object if a connection was made, None otherwise
        """
        socket_details: dict = {}

        # create a listener thread
        listener_thread = threading.Thread(target=self.run_socket_listener, args=(local_host, local_port, socket_details))
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

    @classmethod
    def run_socket_listener(cls, listener_host: str, listener_port: int, socket_details: dict, timeout: float = 5.0) -> None:
        """
        Listens for a connection on a given host and port. If a connection is made, the socket details are stored in the
        socket_details dictionary.

        :param listener_host: The local interface to listen on
        :param listener_port: The local port to listen on
        :param socket_details: A dictionary to store the socket details in.
        :param timeout: The timeout for the socket listener
        :return: None
        """

        # begin with raw sockets, as the pwnlib.remote implementation
        # blocks the thread until a connection is made
        with cls.log.progress("Waiting for connection") as progress:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            try:
                sock.bind((listener_host, listener_port))
            except socket.error as error:
                pwnlib.log.error(error)

            try:
                sock.listen(1)
                conn, addr = sock.accept()
                sock.settimeout(None)
                progress.success(f"Raw socket connected by {addr}")
            except TimeoutError:
                progress.failure("Failed")
                return

        # pass the connection back to the main thread
        socket_details["host"], socket_details["port"] = addr
        socket_details["fam"] = conn.family
        socket_details["type"] = conn.type
        socket_details["conn"] = conn


class SSHAutomation:
    """
    Common functions for SSH test automation
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

    def assert_download_remote_binary(self, remote_path: str, local_path: str) -> bool:
        """
        Confirms a remote file can be downloaded from the target over SSH

        :param remote_path: The remote path to the file
        :param local_path: The local path to save the file to
        :return: True if the file was downloaded, False otherwise
        """
        passed: bool = False

        remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
        if remote_file.exists:
            self.ssh.download_file(remote_path, local_path)
            if os.path.isfile(local_path):
                self.log.debug("Local file does not exist")
                os.remove(local_path)
                passed = True
        else:
            self.log.debug("Remote file does not exist")
        return passed

    def assert_current_user(self, user: str) -> bool:
        """
        Confirms the current user is the expected user

        :param user: expected username
        :return: True if the current user is the expected user, False otherwise
        """
        passed: bool = False
        if self.ssh.connected():
            if self.ssh.user == user:
                passed = True
            else:
                self.log.debug(f"Current user is '{self.ssh.user}' not '{user}'")
        else:
            self.log.warning("SSH connection not established")
        return passed

    def assert_file_exists(self, remote_path: str) -> bool:
        """
        Confirms a file exists on the remote host

        :param remote_path: Location of the expected file
        :return: True if the file exists, False otherwise
        """
        passed: bool = False
        if self.ssh.connected():
            remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
            if remote_file.exists:
                passed = True
            else:
                self.log.debug("Remote file does not exist")
        else:
            self.log.warning("SSH connection not established")

        return passed

    def assert_file_owner(self, remote_path: str, user: str) -> bool:
        """
        Confirms the owner of a file is the expected user

        :param remote_path: Location of the file
        :param user: Expected owner of the file
        :return: True if the file owner is the expected user, False otherwise
        """
        passed: bool = False

        if not self.assert_file_exists(remote_path):
            return False

        remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
        if remote_file.owner == user:
            passed = True
        else:
            self.log.debug(f"File owner is '{remote_file.owner}' not '{user}'")

        return passed

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
        if file_perms == perms:
            passed = True
        else:
            self.log.debug(f"File permissions are '{file_perms}' not '{perms}'")
        return passed

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


def configure_logger():
    """
    Configure the logger for pwntools. Identical to pwnlib.log.configure_logger

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
