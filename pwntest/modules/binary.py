import re
import tempfile
import os

import pwnlib.log
import pwnlib.tubes
import pwnlib.elf
import pwnlib.context
import pwnlib.rop
import pwnlib.asm


# class BinaryAutomation(PwnTestBase):
class BinaryAutomation:
    """
    BinaryAutomation is a class that provides some functionality for interacting
    with executables.
    """

    def __init__(self, binary_path: str = "", ip: str = "", port: int = 0) -> None:
        """
        Initialise the BinaryAutomation class. Inherits the relevant PwnTestBase attributes.

        :param binary_path: path to the binary to test
        :param ip: remote IP address
        :param port: remote port
        :param ssh: pwnlib.tubes.ssh object

        Example:

        >>> import pwntest
        >>> tester = pwntest.PwnTest("demo")
        """
        self.log: pwnlib.log.Logger = pwnlib.log.getLogger("pwntest")

        self.binary_path: str = binary_path
        self.remote_ip: str = ip
        self.remote_port: int = port
        self.remote_test: bool = False
        self.local_test: bool = False

        self.blob_strings_file: tempfile.mkstemp = None
        self.blob_strings_file_name: str = ""

        if self.binary_path:
            self.elf: pwnlib.elf.ELF = pwnlib.elf.ELF(self.binary_path)

    def __del__(self) -> None:
        """
        Clean up the BinaryAutomation class
        """
        if self.blob_strings_file:
            os.remove(self.blob_strings_file_name)

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
        >>> tester.BinaryAutomation.assert_exploit(exploit, flag="flag{", flag_path="/flag")

        **Local Exploit**

        >>> def exploit():
        >>>     s = process("./demo")
        >>>     s.sendline(b"FOOBAR")
        >>>     # shell dropped, so s is a tube into the shell
        >>>     return s
        >>> tester.BinaryAutomation.assert_exploit(exploit, shell=True, remote=False)
        """

        # check the exploit parameter is callable
        if not callable(exploit):
            raise TypeError("Exploit must be a callable function.")

        # check the function has the correct number of parameters
        if exploit.__code__.co_argcount != 2:
            raise ValueError("Exploit function must have 2 parameters: (ip, port)")

        output = exploit(self.remote_ip, self.remote_port)

        if not output:
            self.log.debug("Exploit failed.")
            return False

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

        >>> tester.BinaryAutomation.assert_symbol_exists("main")
        True

        """

        if not self.elf:
            self.log.error("No binary loaded.")
            return False

        return symbol in self.elf.symbols

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

        >>> tester.BinaryAutomation.assert_protections(["NX", "Canary", "PIE", "RELRO Full"])
        [!] Binary does not have stack canary.
        False

        """
        if not self.elf:
            self.log.warning("No binary loaded.")
            return False

        # Cos who even cares about strict typing in python
        if isinstance(protections, str):
            protections = [protections]

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
                    self.log.warning(f"Unknown protection: '{protection}'")
                    return False

        return True

    def assert_rop_gadget_exists(self, gadget: list, deep_search=False) -> bool:
        """
        Check if a ROP gadget exists in the binary.

        :param gadget: Gadget to check for. Same format as pwnlib.rop.rop.ROP.find_gadget()
        :param deep_search: If True, do a more intense search for the gadget. This can return false positives.
        :return: True if gadget exists, False otherwise.

        **Example:**

        >>> tester.BinaryAutomation.assert_rop_gadget_exists(["pop rdi", "ret"])
        False

        >>> tester.BinaryAutomation.assert_rop_gadget_exists(["ret"])
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

    def _extract_binary_strings(self, length: int = 4) -> None:
        """
        Extract strings from the binary.

        :param length: Minimum length of string to extract.
        """

        self.blob_strings_file: tempfile.mkstemp = tempfile.mkstemp()
        self.blob_strings_file_name: str = self.blob_strings_file[1]



        ascii_chars: str = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
        expression: str = '[%s]{%d,}' % (ascii_chars, length)
        pattern: re.Pattern = re.compile(expression.encode())

        blob_strings: list = []
        with open(self.elf.path, "rb") as in_file, \
                open(self.blob_strings_file_name, "w") as out_file:
            while True:
                data: bytes = in_file.read(4096)
                if not data:
                    break
                blob_strings += [i for i in pattern.findall(data)]
            self.log.debug("Found %d strings of length %d or more",
                               len(blob_strings), length)
            out_file.writelines(
                [string.decode() + "\n" for string in blob_strings]
                )

    def get_strings(self, length: int = 4) -> list:
        """
        Length should not be less than 4, as this will return a lot of false positives.
        :param length: Get strings of length
        :return: List of strings of length > length
        """
        if not self.blob_strings_file_name:
            self._extract_binary_strings()

        with open(self.blob_strings_file_name, "rt") as in_file:
            strings: list = in_file.readlines()

        return [string if len(string) > length else None for string in strings]

    def assert_string_exists(self, string: str) -> bool:
        """
        Check if a string exists in the binary.
        Length should not be less than 4, as this will return a lot of false positives.
        :param string: String to check for
        :return: True if string exists, False otherwise.
        """
        str_len: int = len(string)
        if str_len < 4:
            self.log.warning("String to match should be len > 3")
        strings: list = self.get_strings(str_len)
        if string + "\n" in strings:
            return True

        try:
            return string == next(self.elf.search(string.encode()))
        except StopIteration:
            return False

