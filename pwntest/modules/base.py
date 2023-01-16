import pwn
import os


class PwnTestBase:
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
        if binary_path:
            self.local_test = True
            if not os.path.isfile(binary_path):
                raise FileNotFoundError("Local binary target found")
            self.elf = pwn.context.binary = pwn.ELF(self.binary_path, checksec=False)
