import unittest
import os
import threading
import time
import socket

import pwn
import pwnlib.filesystem


def connect_ssh(ip: str, port: int, user: str, password: str = "", keyfile: str = "") -> pwn.ssh:
    ssh: pwn.ssh

    pwn.log.debug(f"Connecting to host {user}@{ip} on port {port}")
    if not password and not keyfile:
        raise ValueError("SSH Password or Keyfile not provided")

    elif password and not keyfile:
        ssh = pwn.ssh(user=user, host=ip, password=password, port=port, )
    elif not password and keyfile:
        ssh = pwn.ssh(user=user, host=ip, keyfile=keyfile, port=port, level="WARNING")
    elif password and keyfile:
        ssh = pwn.ssh(user=user, host=ip, password=password, keyfile=keyfile, port=port, )
    else:
        raise ValueError("Something went wrong with SSH Authentication")

    if not ssh.connected():
        raise ValueError("SSH Connection Failed")
    else:
        pwn.log.info(f"Connected to SSH to remote: {ssh.distro} with remote PID {ssh.pid}")

    return ssh


def run_socket_listener(listener_host: str, listener_port: int, socket_details: dict, timeout: float = 5.0) -> None:
    """
    create a pwntools listener in a new thread that will pass
    a connection back when a connection is made.
    """

    with pwn.log.progress("Waiting for connection") as progress:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        try:
            sock.bind((listener_host, listener_port))
        except socket.error as error:
            pwn.log.error(error)

        try:
            sock.listen(1)
            conn, addr = sock.accept()
            sock.settimeout(None)
            progress.success("Success")
        except TimeoutError:
            progress.failure("Failed")
            return
        pwn.log.debug("Raw socket connected by", addr)

    # pass the connection back to the main thread
    socket_details["host"], socket_details["port"] = addr
    socket_details["fam"] = conn.family
    socket_details["type"] = conn.type
    socket_details["conn"] = conn


class SSHTest:
    def __init__(self, binary_path: str, ip: str, port: int, ssh=None) -> None:
        super().__init__()
        self.remote_ip: str = ip
        self.remote_port: int = port
        self.binary_path: str = binary_path
        self.ssh: pwn.ssh

        if not os.path.isfile(binary_path):
            raise FileNotFoundError("Binary not found")
        self.elf = pwn.context.binary = pwn.ELF(self.binary_path, checksec=False)

        if "user" not in ssh:
            raise ValueError("SSH User not provided")
        if "port" not in ssh:
            ssh["port"] = 22

        if "password" not in ssh and "keyfile" not in ssh:
            pytest.fail("SSH Password or Keyfile not provided")

        if "password" in ssh and "keyfile" in ssh:
            self.ssh = connect_ssh(ip=ip, port=ssh["port"], user=ssh["user"], password=ssh["password"], keyfile=ssh["keyfile"])
        elif "password" in ssh:
            self.ssh = connect_ssh(ip=ip, port=ssh["port"], user=ssh["user"], password=ssh["password"])
        elif "keyfile" in ssh:
            self.ssh = connect_ssh(ip=ip, port=ssh["port"], user=ssh["user"], keyfile=ssh["keyfile"])

    def assert_download_remote_binary(self, remote_path: str, local_path: str) -> bool:
        remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
        if not remote_file.exists:
            print("Remote file does not exist")
            return False

        self.ssh.download_file(remote_path, local_path)
        if not os.path.isfile(local_path):
            print("Local file does not exist")
            return False

        os.remove(local_path)
        return True

    def assert_current_user(self, user: str) -> bool:
        if self.ssh.user != user:
            print(f"Current user is '{self.ssh.user}' not '{user}'")
            return False

        return True

    def assert_file_owner(self, remote_path: str, user: str) -> bool:
        remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
        if remote_file.owner != user:
            print(f"File owner is '{remote_file.owner}' not '{user}'")
            return False

        return True

    def assert_read_perms(self, remote_path: str, readable: bool) -> None:
        remote_file = pwnlib.filesystem.SSHPath(remote_path, ssh=self.ssh)
        if readable:
            try:
                remote_file.open()
            except PermissionError:
                print("")
        elif not readable:
            try:
                remote_file.open()
                self.fail("Error in 'assert_read_perms': Remote file is readable")
            except PermissionError:
                pass
        else:
            raise ValueError("Param 'readable' is not a boolean")


if __name__ == "__main__":
    pwn.context.log_level = 'DEBUG'
    ssh_tester = SSHTest("../challenge", "209.97.129.33", 1337, ssh={"user": "root", "keyfile": "~/.ssh/id_rsa"})
    ssh_tester.assert_download_remote_binary("/etc/passwd", "passwd")
