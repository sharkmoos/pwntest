import ropgadget
import re

import pwnlib.log
import pwnlib.tubes
import pwnlib.elf
import pwnlib.context
import pwnlib.rop
import pwnlib.asm


# class PwnAutomation(PwnTestBase):
class PwnAutomation:
    """
    PwnAutomation is a class that provides some functionality for checking properties of executables
    """
    def __init__(self, binary_path: str, ip: str = "", port: int = 0, ssh=None) -> None:
        """
        Initialise the PwnAutomation class. Inherits the relevant PwnTestBase attributes.

        :param binary_path: path to the binary to test
        :param ip: remote IP address
        :param port: remote port
        :param ssh: pwnlib.tubes.ssh object

        Example:

        >>> import pwntest
        >>> tester = pwntest.PwnTest("demo")
        """
        self.rop: pwnlib.rop.rop = None
        self.elf: pwnlib.elf.elf = None
        self.process: pwnlib.tubes.process.process = None
        self.ssh: pwnlib.tubes.ssh = ssh
        self.log: pwnlib.log.Logger = pwnlib.log.getLogger("pwntest")

        self.binary_path: str = binary_path
        self.remote_ip: str = ip
        self.remote_port: int = port
        self.remote_test: bool = False
        self.local_test: bool = False

        if self.binary_path:
            self.elf = pwnlib.elf.ELF(self.binary_path)

    def assert_exploit(self, exploit, flag="", flag_path="", remote: bool = True) -> bool:
        """
        Assert an exploit drops a shell or returns a flag. A few important things

        * A remote exploit must have the following signature: def exploit(ip, port)
        * A local exploit must have the following signature: def exploit()
        * flag and flag_path must be supplied together, or not at all. If not supplied, the exploit should drop a shell
        * If the exploit drops a shell, the shell should be returned by the exploit function

        :param exploit: a python function that either returns a shell or a flag string, as specified by params supplied to the function.
        :param flag: Flag inside the flag file
        :param flag_path: Path to the flag file
        :param remote: If True, the exploit function will be passed the remote IP and port parameters.

        :return: True if the exploit works, False otherwise

        **Examples:**

        **Remote Exploit**


        >>> def exploit(ip, port):
        >>>     s = remote(ip, port)
        >>>     s.sendline(b"cat /flag")
        >>>     return s.recvline_contains(b"flag{")
        >>> tester.PwnAutomation.assert_exploit(exploit, flag="flag{", flag_path="/flag")

        **Local Exploit**

        >>> def exploit():
        >>>     s = process("./demo")
        >>>     s.sendline(b"FOOBAR")
        >>>     # shell dropped, so s is a tube into the shell
        >>>     return s
        >>> tester.PwnAutomation.assert_exploit(exploit, shell=True, remote=False)
        """

        # check the exploit parameter is callable
        if not callable(exploit):
            raise TypeError("Exploit must be a callable function.")

        # check the function has the correct number of parameters
        if exploit.__code__.co_argcount != 2:
            raise ValueError("Exploit function must have 2 parameters: (ip, port)")

        output = exploit(self.remote_ip, self.remote_port)

        if not flag and not flag_path:
            output.sendline(b"echo FOOBAR")
            passed = b"FOOBAR" in output.recvline_contains(b"FOOBAR", timeout=1)
            output.close()

        elif flag and flag_path:
            passed = flag.encode() in output if isinstance(flag, str) else flag in output
        else:
            raise ValueError("Must supply either (flag and flag_path) or neither.")

        return passed

    def assert_symbol_exists(self, symbol: str) -> bool:
        """
        Check if a symbol exists in the binary.

        :param symbol: Symbol to check for
        :return: True if symbol exists, False otherwise.

        **Example:**

        >>> tester.PwnAutomation.assert_symbol_exists("main")
        True

        """

        if self.elf:
            passed: bool = symbol in self.elf.symbols
        else:
            self.log.error("No binary loaded.")
            return False

        return passed

    def assert_protections(self, protections: list) -> bool:
        """
        Check if a list of string protection names are present in the binary.

        Options:

        * NX || NX Stack
        * Canary || Stack Canary || Stack Protector
        * PIE || Position Independent Executable
        * RELRO Full || Full RELRO
        * RELRO Partial || Partial RELRO

        :param protections: List of protections to check for
        :return: True if all protections are present, False otherwise.

        Example:

        >>> tester.PwnAutomation.assert_protections(["NX", "Canary", "PIE", "RELRO Full"])
        [!] Binary does not have stack canary.
        False

        """
        if not self.elf:
            self.log.error("No binary loaded.")
            return False

        for protection in protections:
            protection = protection.lower()
            match protection:
                # case nx or nx stack
                case "nx" | "nx stack" | "non-exec" | "non-exec stack":
                    if self.elf.execstack:
                        self.log.warning("Binary is NX enabled.")
                        return False
                case "canary" | "stack canary" | "stack protector":
                    if not self.elf.canary:
                        self.log.warning("Binary does not have stack canary.")
                        return False
                case "pie" | "position independent executable":
                    if not self.elf.pie:
                        self.log.warning("Binary is not PIE enabled.")
                        return False
                case "relro full" | "full relro":
                    if self.elf.relro != "Full":
                        self.log.warning("Binary is not Full RELRO enabled.")
                        return False
                case "relro partial" | "partial relro":
                    if self.elf.relro != "Partial":
                        self.log.warning("Binary is not Partial RELRO enabled.")
                        return False
                case _:
                    self.log.error(f"Unknown protection: '{protection}'")

        return True

    def assert_rop_gadget_exists(self, gadget: list, deep_search=False) -> bool:
        """
        Check if a ROP gadget exists in the binary.

        :param gadget: Gadget to check for. Same format as pwnlib.rop.rop.ROP.find_gadget()
        :param deep_search: If True, do a more intense search for the gadget. This can return false positives.
        :return: True if gadget exists, False otherwise.

        **Example:**

        >>> tester.PwnAutomation.assert_rop_gadget_exists(["pop rdi", "ret"])
        False

        >>> tester.PwnAutomation.assert_rop_gadget_exists(["ret"])
        True

        """
        self.rop: pwnlib.rop.rop.ROP = pwnlib.rop.ROP(self.elf)

        gadget_addr: int = self.rop.find_gadget(gadget)

        if not gadget_addr:
            self.log.debug(f"Gadget '{gadget}' not found in using pwntools in binary: {self.binary_path}")
            if deep_search:
                self.log.debug("Performing deep search, this could take a while...")
                # assemble the code and try and find a match in the binary
                code = pwnlib.asm.asm("\n".join(gadget), arch=self.elf.arch)
                try:
                    gadget_addr = next(self.elf.search(code, executable=True))
                    self.log.debug(f"Gadget '{gadget_addr}' found in binary: {self.binary_path} using deep search")
                except StopIteration:
                    pass

        return gadget_addr is not None
