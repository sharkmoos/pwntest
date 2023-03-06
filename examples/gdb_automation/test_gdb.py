#!/usr/bin/python

import pwnlib.gdb
import pwnlib.context
import pwnlib.elf
import pwnlib.tubes
import sys
import os

sys.path.append(os.getcwd())
import pwntest

# elf = pwnlib.context.binary = pwnlib.elf.ELF('demo')
elf = pwnlib.context.binary = pwnlib.elf.ELF('examples/gdb_automation/demo')
os.system(f"chmod +x {elf.path}")


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


def test_reg_read():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main+52")
    p.sendline(b"A" * 8)
    api.continue_and_wait()

    # rax should be 8, because we sent 8 bytes of data
    assert api.read_reg("rax") == 8
    api.quit()


def test_get_section_base():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    stack_addr = api.get_section_base(api.get_pid(), "[stack]")
    print(f"Stack Address: {hex(stack_addr)}")
    assert stack_addr
    api.quit()


def test_memory_read():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main+52")
    p.sendline(b"FOOBAR")
    api.continue_and_wait()

    # pointer in rdi should be "FOOBAR"
    memory = b"".join([i for i in api.read_mem(api.read_reg("rdi"), 6)])

    print(f"Memory: {memory}")
    assert memory == b"FOOBAR"
    api.quit()


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


# def test_debug():
#     p = pwntest.extended_gdb.test_debug(elf.path)
#     test_breakpoint()


def test_run_command():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main")

    # write and check
    data = int.from_bytes(b"A" * 8, byteorder="little")
    api.run_command("set $rdi = 0x4141414141414141")
    assert api.read_reg("rdi") == data
    api.quit()


def test_is_running():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    api.Breakpoint("*main")
    assert not api.is_running()

    api.continue_nowait()
    assert api.is_running()

    api.quit()

def test_addr_from_symbol():
    p = pwnlib.tubes.process.process([elf.path])
    gdb_proc, api = pwntest.extended_gdb.test_attach(p)

    assert int(api.address_from_symbol("main")) - api.get_binary_base() == elf.sym.main
    api.quit()
