import sys
import os
from exploit import get_flag as exploit_flag
from exploit import get_shell as exploit_shell
import pytest

sys.path.append(os.getcwd())
import pwntest

tester = pwntest.PwnTest("127.0.0.1", 9001, binary_path="examples/pwn_automation/challenge/challenge")


def failed_exploit(a, b):
    return False


def bad_exploit():
    return False


@pytest.mark.example
def test_assert_exploit():
    assert tester.BinaryAutomation.assert_exploit(exploit=exploit_flag, flag="cueh{test_flag}", ip=tester.remote_ip, port=tester.remote_port)
    assert tester.BinaryAutomation.assert_exploit(exploit=exploit_shell, ip=tester.remote_ip, port=tester.remote_port)

    assert tester.BinaryAutomation.assert_exploit(exploit=exploit_flag, flag="cueh{", ip=tester.remote_ip, port=tester.remote_port)
    assert tester.BinaryAutomation.assert_exploit(exploit=exploit_shell, flag="cueh{", flag_path="/flag", ip=tester.remote_ip, port=tester.remote_port)

@pytest.mark.example
def test_assert_symbol_exists():
    assert tester.BinaryAutomation.assert_symbol_exists("main")


@pytest.mark.example
def test_assert_protections():
    assert tester.BinaryAutomation.assert_protections(["NX", "partial relro"])


@pytest.mark.example
def test_assert_rop_gadget_exists():
    assert tester.BinaryAutomation.assert_rop_gadget_exists(["ret"])

    # pwntools does not do JOP
    assert not tester.BinaryAutomation.assert_rop_gadget_exists(["jmp rax"])
    assert tester.BinaryAutomation.assert_rop_gadget_exists(["jmp rax"], deep_search=True)


def test_assert_string_exists():
    assert tester.BinaryAutomation.assert_string_exists("main")  # symbol
    assert tester.BinaryAutomation.assert_string_exists("/flag")  # data
    assert not tester.BinaryAutomation.assert_string_exists("FOOBAR")  # not in binary


# =========== UNIT TESTS NOT EXAMPLE =================

def test_unit_assert_exploit():
    with pytest.raises(TypeError) as e_info:
        tester.BinaryAutomation.assert_exploit(exploit="", flag="cueh{", flag_path="/flag")


@pytest.mark.parametrize("sym", [
    ("main", True),
    ("puts", True),
    (1, False),
    ("", False),
    ("not_a_symbol", False),
])
def test_unit_assert_symbol_exists(sym: str):
    print(sym)
    assert tester.BinaryAutomation.assert_symbol_exists(sym[0]) == sym[1]


@pytest.mark.parametrize("lst", [
    (["NX", "relro pArTiAl"], True),
    (["nX", "relro pArTiAl"], True),
    (["NX"], True),
    ("NX", True),
    ("canary", False),
    ("FOOBAR", False),
    (["FOOBAR", "BARFOO"], False),
])
def test_unit_assert_protections(lst):
    assert tester.BinaryAutomation.assert_protections(lst[0]) == lst[1]


def test__del__():
    t = pwntest.PwnTest("127.0.0.1", 9001, binary_path="examples/pwn_automation/challenge/challenge")
    t.BinaryAutomation.get_strings(4)
    blob_file_path = t.BinaryAutomation.blob_strings_file_name
    del t
    assert not os.path.exists(blob_file_path)
