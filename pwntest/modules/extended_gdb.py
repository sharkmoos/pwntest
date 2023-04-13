"""
TODO:
    - Remove unnecessary code and args from test_debug and test_attach
    - Setting breakpoints etc causes a crash if the program is running. Do a check
        before actually doing these ops
"""

import os
import subprocess
import tempfile
import six.moves
import socket
import time
import platform
import atexit
import random

import pwnlib
import pwnlib.gdb
import pwnlib.log
import pwnlib.tubes
import pwnlib.qemu

from pwnlib.util import proc
from pwnlib.timeout import Timeout


log: pwnlib.log.Logger = pwnlib.log.getLogger("pwntest")


class ExtendedGdb(pwnlib.gdb.Gdb):
    """
    Extend the functionality of the pwnlib.gdb.Gdb class by providing wrappers
    around the gdb API. GDB does not run in a terminal window, so running unit
    tests and programmatically operating on the debugged program easier.

    Currently, this has only been tested on single-threaded programs,
    however it should work in the same way as just using the gdb api directly.
    """

    # def __init__(self, conn: rpyc.core.protocol.Connection, binary_path: str):
    def __init__(self, conn, binary_path: bytes):
        """
        Constructor. Starts a gdb process and adds it to the global
        list of gdb processes.

        :param conn:
        :param binary_path:
        """
        super().__init__(conn)

        # if initialised with gdb.debug, the name may not be passed
        self.binary_base = None
        self.section_bases: dict = {}
        self._target = None

        if not binary_path:
            with open(f"/proc/{self.selected_inferior().pid}/cmdline", "rt") as f:
                self.binary_path = f.read().strip().strip("\x00")
        else:
            self.binary_path: str = binary_path.decode()

        atexit.register(self.__del__)

    def __del__(self) -> None:
        """
        Destructor. Terminate the gdb process and remove it from the global
         list of gdb processes.

        :return:
        """
        self.close()

    # @staticmethod
    # def cleanup() -> None:
    #     """
    #     Cleanup function. Called when the program exits.
    #     Terminates all gdb processes.
    #
    #     :return:
    #     """
    #     if len(gdb_procs) > 0:
    #         for process in gdb_procs:
    #             try:
    #                 gdb_procs[process].terminate()
    #             except EOFError:
    #                 pass

    def run_command(self, command: str) -> None:
        """
        Run a command in the gdb process.
        No checks are performed to see if the command is or ran successfully.

        :param command: Command to run
        :return: None
        """
        self.execute(command)

    def is_running(self) -> bool:
        """
        Check if the debugged program is running.

        :return: True if running, False if not
        """
        # running_threads = [t.is_running() for t in self.selected_inferior().threads()]
        # for thread in running_threads:
        #     if thread:
        #         return True
        # return False
        return self.selected_inferior().threads()[0].is_running()

    def get_pid(self) -> int:
        """
        Get the PID of the debugged process.

        :return: PID of current debugged process.
            Returns 0 if no process is running.
        """
        pid: int = self.selected_inferior().pid
        log.debug(f"Current PID is {pid}")
        if not pid:
            log.info("Program is not running")
        return pid

    def close(self) -> None:
        """
        Close the gdb process and the debugged program in one go.

        :return: None
        """

        try:
            self.quit()

            if isinstance(self._target, pwnlib.tubes.process.process):
                if self._target.proc is None:
                    return

                # First check if we are already dead
                self._target.poll(False)

                # close file descriptors
                for fd in [self._target.proc.stdin,
                           self._target.proc.stdout, self._target.proc.stderr]:
                    if fd is not None:
                        try:
                            fd.close()
                        except IOError as e:
                            if e.errno != self.EPIPE:
                                raise

                if not self._target._stop_noticed:
                    self._target.proc.kill()
                    self._target.proc.wait()
                    self._target._stop_noticed = time.time()

        except OSError:
            pass
        except EOFError:
            pass

    def get_section_base(self, section_name: str) -> int:
        """
        Get the base address of a section.
         Should match the name from /proc/<pid>/maps

        :param current_pid: Process ID of file to read from
        :param section_name: Name of section to get base address of
        :return: Base address of section or -1 if not found
        """

        if section_name in self.section_bases:
            return self.section_name_base[section_name]

        current_pid: int = self.get_pid()
        # check file exists, process could have ended
        if not os.path.exists(f"/proc/{current_pid}/maps"):
            log.warning(f"File '/proc/{current_pid}/maps' does not exist")
            return 0

        with open(f"/proc/{current_pid}/maps", "rt") as maps_file:
            for line in maps_file:
                current_section_name: str = line.split("  ")[-1].strip()
                # some sections have a name in square brackets ([stack]),
                # but lets not force the user to have to write that
                if (section_name if not current_section_name.startswith("[")
                                    or section_name.startswith("[")
                else f"[{section_name}]") == current_section_name:
                    base: int = int(line.split("-")[0], 16)
                    log.debug(f"{section_name}: {hex(base)}")
                    self.section_bases[section_name] = base
                    return base

        log.warning(f"Section '{section_name}' not found")
        return 0

    def get_binary_base(self) -> int:
        """
        Get the base address of the binary currently being debugged

        :return: Base address of binary. -1 if not found
        """
        if "binary_base" not in self.section_bases:
            self.section_bases["binary_base"]: int = self.get_section_base(self.binary_path)
            if self.binary_base == 0:
                log.warning("Could not find base address of binary")
        return self.section_bases["binary_base"]

    def address_from_symbol(self, symbol: str) -> int:
        """
        Get the address of a symbol

        :param symbol: Symbol to get address of
        :return: Address of symbol. 0 if symbol not found
        """

        sym = self.lookup_symbol(symbol)[0]

        if sym is None:
            log.debug(f"Symbol '{symbol}' not found")
        elif not sym.is_function:
            log.debug(f"Symbol '{symbol}' is not a function")
        else:
            return sym.value().address

        return 0

    def read_mem(self, addr: int, length: int) -> bytes:
        """
        Read memory from a given address

        :param addr: Address to read from
        :param length: Number of bytes to read
        :return: gdb.Value object of the value
        """

        if self.is_running():
            log.warning("Reading from memory while program is running can "
                        "cause unexpected behaviour")

        return self.inferiors()[0].read_memory(addr, length).tobytes()

    def read_reg(self, register: str) -> int:
        """
        Read value from a register.

        :param register: Register to read from
        :return: gdb.Value object of the value.
        """

        if self.is_running():
            log.warning("Reading from memory while program is running can "
                        "cause unexpected behaviour")

        if not register.startswith("$"):
            register: str = "$" + register

        value: int = self.parse_and_eval(register)
        if value == "void":
            log.warning(f"Register '{register}' does not exist in this context")

        return int(value)

    def read_regs(self, registers: list) -> dict:
        """
        Read value from multiple register.
        Wrapper around newest_frame().read_register().

        :param registers: List of registers to read from
        :return: Dict of register: gdb.Value
        """

        results: dict = {}
        for register in registers:
            results[register] = self.read_reg(register)

        return results

    def write_reg(self, register: str, value: int) -> bool:
        """
        Write a value to a register

        :param register: Register to write to
        :param value: Value to write
        :return: True if successful, False if not
        """
        if self.is_running():
            log.warning("Writing to registers while program is running can "
                        "cause unexpected behaviour")

        if not register.startswith("$"):
            register = "$" + register

        if self.parse_and_eval(register) == "void":
            log.warning(f"Register '{register}' does not exist in this context")
            return False

        if not isinstance(value, int):
            log.error("Data must be entered as an int")

        # TODO: Find a better way to write to a register
        self.execute(f"set {register} = {value}")
        if self.parse_and_eval(register) != value:
            log.warning(f"Failed to write to register '{register}'")
            return False

        return True

    def write_mem(self, address: int, value: bytes) -> bool:
        """
        Write a value to a register

        :param address: Register to write to
        :param value: Value to write
        :return: None
        """
        if self.is_running():
            log.warning("Writing to memory while program is running can "
                        "cause unexpected behaviour")

        self.inferiors()[0].write_memory(address, value)
        if self.read_mem(address, len(value)) != value:
            log.warning(f"Failed to write to memory '{hex(address)}'")
            return False
        else:
            return True

    def match_reg_value(self, register: str, value: int) -> bool:
        """
        Check that the expected value of a register matches the value in memory

        :param register: register to check
        :param value: expected value
        :return:
        """
        if self.is_running():
            log.warning("Reading from registers while program is running can "
                        "cause unexpected behaviour")

        register_value: int = self.read_reg(register)
        return register_value == value

    def check_regs_value(self, registers: dict) -> dict:
        """
        Checks that the expected values in a dictionary of registers
        match the actual values in memory.

        :param registers: Dictionary of register names and values to check,
            e.g. {"rax": 0xdeadbeef}
        :return: Dictionary of register names and values with fields matched
            (bool), expected (int), actual (int)
        """

        # TODO: See if this implementation of reading registers
        #  or parse and eval is better

        if self.is_running():
            log.warning("Reading from memory while program is running can "
                        "cause unexpected behaviour")

        results: dict = {}
        for register in registers.keys():
            register_value = self.newest_frame().read_register(register)
            try:
                results[register] = {
                    "match": register_value == registers[register],
                    "expected": registers[register],
                    "actual": register_value
                }
            except TypeError:
                raise Exception(f"Expected value for register '{register}' "
                                "is wrong type")

        return results


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
def debug(args, gdbscript=None, exe=None, ssh=None, env=None,
          sysroot=None, api=True, **kwargs):
    """
    Identical to the gdb.debug() function, runs gdb as a subprocess rather than in a terminal window.
    This code is taken from the pwntools gdb module under MIT license:
    https://github.com/Gallopsled/pwntools/blob/c45e92d78b3fc6ecf0a3b839417bbaee2e54637c/pwnlib/gdb.py#L366
    """
    if isinstance(args, six.integer_types + (pwnlib.tubes.process.process, pwnlib.tubes.ssh.ssh_channel)):
        log.error("Use gdb.attach() to debug a running process")

    if isinstance(args, (bytes, six.text_type)):
        args = [args]

    if isinstance(args, str):
        args = [args.encode()]

    orig_args = args

    runner = pwnlib.gdb._get_runner(ssh)
    which = pwnlib.gdb._get_which(ssh)
    gdbscript = gdbscript or ''

    if api and runner is not pwnlib.tubes.process.process:
        raise ValueError('GDB Python API is supported only for local processes')

    args, env = pwnlib.util.misc.normalize_argv_env(args, env, log)
    if env:
        env = {bytes(k): bytes(v) for k, v in env}

    if pwnlib.context.context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return runner(args, executable=exe, env=env)

    if ssh or pwnlib.context.context.native or (pwnlib.context.context.os == 'android'):
        args = pwnlib.gdb._gdbserver_args(args=args, which=which, env=env)
    else:
        qemu_port = random.randint(1024, 65535)
        qemu_user = pwnlib.qemu.user_path()
        sysroot = sysroot or pwnlib.qemu.ld_prefix(env=env)
        if not qemu_user:
            log.error("Cannot debug %s binaries without appropriate QEMU binaries" % pwnlib.context.context.arch)
        if pwnlib.context.context.os == 'baremetal':
            qemu_args = [qemu_user, '-S', '-gdb', 'tcp::' + str(qemu_port)]
        else:
            qemu_args = [qemu_user, '-g', str(qemu_port)]
        if sysroot:
            qemu_args += ['-L', sysroot]
        args = qemu_args + args

    # Make sure gdbserver/qemu is installed
    if not which(args[0]):
        log.error("%s is not installed" % args[0])

    if not ssh:
        exe = exe or which(orig_args[0])
        if not (exe and os.path.exists(exe)):
            log.error("%s does not exist" % exe)

    # Start gdbserver/qemu
    # (Note: We override ASLR here for the gdbserver process itself.)
    gdbserver = runner(args, env=env, aslr=1, **kwargs)

    # Set the .executable on the process object.
    gdbserver.executable = exe

    # Find what port we need to connect to
    if pwnlib.context.context.native or (pwnlib.context.os == 'android'):
        port = pwnlib.gdb._gdbserver_port(gdbserver, ssh)
    else:
        port = qemu_port

    host = '127.0.0.1'
    if not ssh and pwnlib.context.os == 'android':
        host = pwnlib.context.adb_host

    tmp = attach((host, port), exe=exe, gdbscript=gdbscript, ssh=ssh, sysroot=sysroot, api=api)
    _, gdb = tmp
    gdbserver.gdb = gdb

    # gdbserver outputs a message when a client connects
    garbage = gdbserver.recvline(timeout=1)

    # Some versions of gdbserver output an additional message
    garbage2 = gdbserver.recvline_startswith(b"Remote debugging from host ", timeout=2)

    return gdbserver, gdb


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
def attach(target, gdbscript="", exe=None, gdb_args=None, ssh=None,
           sysroot=None, api=True):
    """
    Minor change to the gdb.attach() function, runs gdb as a subprocess
    rather than in a terminal window.

    The majority of this code is taken from the pwntools gdb module under MIT license:
    https://github.com/Gallopsled/pwntools/blob/c45e92d78b3fc6ecf0a3b839417bbaee2e54637c/pwnlib/gdb.py#L720

    :param target:
    :param gdbscript:
    :param exe:
    :param gdb_args:
    :param ssh:
    :param sysroot:
    :param api:
    :return:
    """
    if pwnlib.context.context.noptrace:
        log.warn_once("Skipping debug attach since "
                      "pwnlib.context.context.noptrace==True")
        return

    # if gdbscript is a file object, then read it; we probably need to run some
    # more gdb script anyway
    if hasattr(gdbscript, 'read'):
        with gdbscript:
            gdbscript = gdbscript.read()

    # enable gdb.attach(p, 'continue')
    if gdbscript and not gdbscript.endswith('\n'):
        gdbscript += '\n'

    # Use a sane default sysroot for Android
    if not sysroot and pwnlib.context.context.os == 'android':
        sysroot = 'remote:/'

    # gdb script to run before `gdbscript`
    pre = ''
    if sysroot:
        pre += 'set sysroot %s\n' % sysroot
    if not pwnlib.context.context.native:
        pre += 'set endian %s\n' % pwnlib.context.context.endian
        pre += 'set architecture %s\n' % pwnlib.gdb.get_gdb_arch()

        if pwnlib.context.context.os == 'android':
            pre += 'set gnutarget ' + pwnlib.asm._bfdname() + '\n'

        if exe and pwnlib.context.context.os != 'baremetal':
            pre += 'file "%s"\n' % exe

    # let's see if we can find a pid to attach to
    pid = None
    if isinstance(target, six.integer_types):
        # target is a pid, easy peasy
        pid = target
    elif isinstance(target, str):
        # pidof picks the youngest process
        pidof = proc.pidof

        if pwnlib.context.context.os == 'android':
            pidof = pwnlib.adb.pidof

        pids = list(pidof(target))
        if not pids:
            log.error('No such process: %s', target)
        pid = pids[0]
        log.info('Attaching to youngest process "%s" (PID = %d)' %
                 (target, pid))
    elif isinstance(target, pwnlib.tubes.ssh.ssh_channel):
        if not target.pid:
            log.error("PID unknown for channel")

        shell = target.parent

        tmpfile = shell.mktemp()
        gdbscript = b'shell rm %s\n%s' % (tmpfile,
                                          pwnlib.util.packing._need_bytes(
                                              gdbscript, 2, 0x80))
        shell.upload_data(gdbscript or b'', tmpfile)

        cmd = ['ssh', '-C', '-t', '-p', str(shell.port), '-l',
               shell.user, shell.host]
        if shell.password:
            if not pwnlib.util.misc.which('sshpass'):
                log.error("sshpass must be installed to debug ssh processes")
            cmd = ['sshpass', '-p', shell.password] + cmd
        if shell.keyfile:
            cmd += ['-i', shell.keyfile]
        cmd += ['gdb', '-q', target.executable, str(target.pid), '-x', tmpfile]

        pwnlib.util.misc.run_in_new_terminal(cmd)
        return

    elif isinstance(target, pwnlib.tubes.sock.sock):
        pids = proc.pidof(target)
        if not pids:
            log.error('Could not find remote process (%s:%d) on this machine' %
                      target.sock.getpeername())
        pid = pids[0]

        # Specifically check for socat, since it has an intermediary process
        # if you do not specify "nofork" to the EXEC: argument
        # python(2640)───socat(2642)───socat(2643)───bash(2644)
        if proc.exe(pid).endswith('/socat') and time.sleep(0.1) and proc.children(pid):
            pid = proc.children(pid)[0]

        # We may attach to the remote process after the fork but before it performs an exec.
        # If an exe is provided, wait until the process is actually running the expected exe
        # before we attach the debugger.
        t = Timeout()
        with t.countdown(2):
            while exe and os.path.realpath(proc.exe(pid)) != os.path.realpath(exe) and t.timeout:
                time.sleep(0.1)

    elif isinstance(target, pwnlib.tubes.process.process):
        pid = proc.pidof(target)[0]
        exe = exe or target.executable
    elif isinstance(target, tuple) and len(target) == 2:
        host, port = target

        if pwnlib.context.context.os != 'android':
            pre += 'target remote %s:%d\n' % (host, port)
        else:
            # Android debugging is done over gdbserver, which can't follow
            # new inferiors (tldr; follow-fork-mode child) unless it is run
            # in extended-remote mode.
            pre += 'target extended-remote %s:%d\n' % (host, port)
            pre += 'set detach-on-fork off\n'

        def findexe():
            for spid in proc.pidof(target):
                sexe = proc.exe(spid)
                name = os.path.basename(sexe)
                # XXX: parse cmdline
                if name.startswith('qemu-') or name.startswith('gdbserver'):
                    exe = proc.cmdline(spid)[-1]
                    return os.path.join(proc.cwd(spid), exe)

        exe = exe or findexe()
    elif isinstance(target, pwnlib.elf.corefile.Corefile):
        pre += 'target core "%s"\n' % target.path
    else:
        log.error("don't know how to attach to target: %r", target)

    # if we have a pid but no exe, just look it up in /proc/
    if pid and not exe:
        exe_fn = proc.exe
        if pwnlib.context.context.os == 'android':
            exe_fn = pwnlib.adb.proc_exe
        exe = exe_fn(pid)

    if not pid and not exe and not ssh:
        log.error('could not find target process')

    gdb_binary = pwnlib.gdb.binary()
    cmd = [gdb_binary]

    if gdb_args:
        cmd += gdb_args

    if pwnlib.context.context.gdbinit:
        cmd += ['-nh']  # ignore ~/.gdbinit
        cmd += ['-x', pwnlib.context.context.gdbinit]  # load custom gdbinit

    cmd += ['-q']

    if exe and pwnlib.context.context.native:
        if not ssh and not os.path.isfile(exe):
            log.error('No such file: %s', exe)
        cmd += [exe]

    if pid and not pwnlib.context.context.os == 'android':
        cmd += [str(pid)]

    if pwnlib.context.context.os == 'android' and pid:
        runner = pwnlib.gdb._get_runner()
        which = pwnlib.gdb._get_which()
        gdb_cmd = pwnlib.gdb._gdbserver_args(pid=pid, which=which)
        gdbserver = runner(gdb_cmd)
        port = pwnlib.gdb._gdbserver_port(gdbserver, None)
        host = pwnlib.context.context.adb_host
        pre += 'target extended-remote %s:%i\n' % (
            pwnlib.context.context.adb_host, port)

        # gdbserver on Android sets 'detach-on-fork on' which breaks things
        # when you're trying to debug anything that forks.
        pre += 'set detach-on-fork off\n'

    if api:
        # create a UNIX socket for talking to GDB
        socket_dir = tempfile.mkdtemp()
        socket_path = os.path.join(socket_dir, 'socket')
        bridge = os.path.join(os.path.dirname(__file__), 'gdb_api_bridge.py')

        # inject the socket path and the GDB Python API bridge
        pre = 'python socket_path = ' + repr(socket_path) + '\n' + \
              'source ' + bridge + '\n' + \
              pre

    gdbscript = pre + (gdbscript or '')

    if gdbscript:
        tmp = tempfile.NamedTemporaryFile(prefix='pwn', suffix='.gdb',
                                          delete=False, mode='w+')
        # log.debug('Wrote gdb script to %r\n%s', tmp.name, gdbscript)
        gdbscript = 'shell rm %s\n%s' % (tmp.name, gdbscript)

        tmp.write(gdbscript)
        tmp.close()
        cmd += ['-x', tmp.name]

    log.debug('Running as subprocess: %s', cmd)

    if api:
        # prevent gdb_faketerminal.py from messing up api doctests
        def preexec_fn():
            os.environ['GDB_FAKETERMINAL'] = '0'
    else:
        preexec_fn = None

    gdb_proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    gdb_pid = gdb_proc.pid
    # gdb_pid = pwnlib.util.misc.run_in_new_terminal(cmd, preexec_fn = preexec_fn)
    log.debug(f"Running GDB in process {gdb_pid}")

    if pid and pwnlib.context.context.native:
        proc.wait_for_debugger(pid, gdb_pid)

    if not api:
        return gdb_pid

    # connect to the GDB Python API bridge
    from rpyc import BgServingThread
    from rpyc.utils.factory import unix_connect
    if six.PY2:
        retriable = socket.error
    else:
        retriable = ConnectionRefusedError, FileNotFoundError

    t = Timeout()
    with t.countdown(10):
        while t.timeout:
            try:
                conn = unix_connect(socket_path)
                break
            except retriable:
                time.sleep(0.1)
        else:
            # Check to see if RPyC is installed at all in GDB
            rpyc_check = [gdb_binary, '--nx', '-batch', '-ex',
                          'python import rpyc; import sys; sys.exit(123)']

            if 123 != pwnlib.tubes.process.process(rpyc_check).poll(block=True):
                log.error('Failed to connect to GDB: rpyc is not installed')

            # Check to see if the socket ever got created
            if not os.path.exists(socket_path):
                log.error(
                    'Failed to connect to GDB: Unix socket %s was never created',
                    socket_path)

            # Check to see if the remote RPyC client is a compatible version
            version_check = [gdb_binary, '--nx', '-batch', '-ex',
                             'python import platform; print(platform.python_version())']
            gdb_python_version = pwnlib.tubes.process.process(version_check).recvall().strip()
            python_version = str(platform.python_version())

            if gdb_python_version != python_version:
                log.error('Failed to connect to GDB: Version mismatch (%s vs %s)',
                          gdb_python_version,
                          python_version)

            # Don't know what happened
            log.error('Failed to connect to GDB: Unknown error')

    # now that connection is up, remove the socket from the filesystem
    os.unlink(socket_path)
    os.rmdir(socket_dir)

    # create a thread for receiving breakpoint notifications
    BgServingThread(conn, callback=lambda: None)
    argv0 = b""
    if isinstance(target, pwnlib.tubes.process.process):
        argv0 = target.argv[0]

    gdb_proc = ExtendedGdb(conn, argv0)
    gdb_proc._target = target

    return gdb_pid, gdb_proc

