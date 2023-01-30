#!/usr/bin/python

import pwnlib.gdb
import pwnlib.context
import pwnlib.elf
import pwnlib.tubes
import sys

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

# elf = pwnlib.context.binary = pwnlib.elf.ELF('demo')
elf = pwnlib.context.binary = pwnlib.elf.ELF('examples/gdb_utils/demo')


def test_breakpoint():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main+52")
    p.sendline(b"FOOBAR")
    api.continue_and_wait()

    # pc should be at main+52
    expected_pc = api.get_binary_base() + elf.sym.main + 52
    actual_pc = api.read_reg("rip")

    print("Expected PC: ", hex(expected_pc))
    print("Actual PC: ", hex(actual_pc))
    assert expected_pc == actual_pc

    api.quit()
    p.close()


def test_reg_read():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main+52")
    p.sendline(b"A" * 8)
    api.continue_and_wait()

    # rax should be 8, because we sent 8 bytes of data
    assert api.read_reg("rax") == 8
    api.quit()
    p.close()

def test_memory_read():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main+52")
    p.sendline(b"FOOBAR")
    api.continue_and_wait()

    # stack pointer in rdi should be "FOOBAR"
    memory = b"".join([i for i in api.read_mem(api.read_reg("rdi"), 6)])

    print(f"Memory: {memory}")
    assert memory == b"FOOBAR"
    api.quit()
    p.close()

def test_write_mem():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main+52")
    p.sendline(b"FOOBAR")
    api.continue_and_wait()

    stack_addr = api.get_section_base(api.get_pid(), "[stack]")

    # write and check
    data = b"A" * 8
    api.write_mem(stack_addr, data)
    new_data = b"".join([i for i in api.read_mem(stack_addr, 8)])
    assert new_data == data
    api.quit()
    p.close()


def test_write_reg():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main+52")
    p.sendline(b"FOOBAR")
    api.continue_and_wait()

    # write and check
    data = int.from_bytes(b"A" * 8, byteorder="little")
    api.write_reg("rdi", data)
    assert api.read_reg("rdi") == data
    api.quit()
    p.close()


def test_debug():
    p = pwntest.extended_gdb.test_debug(elf.path)
    test_breakpoint()
