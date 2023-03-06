import sys
from exploit import get_flag as exploit_flag
from exploit import get_shell as exploit_shell
import pytest

sys.path.append("/mnt/c/Users/Muddy/OneDrive/Uni/Dissertation/pwntest/")
import pwntest

tester = pwntest.PwnTest("127.0.0.1", 9001, binary_path="examples/pwn_automation/challenge/challenge")


def failed_exploit(a, b):
    return False


def bad_exploit():
    return False


def test_assert_exploit():
    assert tester.BinaryAutomation.assert_exploit(exploit=exploit_flag, flag="cueh{", flag_path="/flag")
    assert tester.BinaryAutomation.assert_exploit(exploit=exploit_shell, remote=True)

    assert not tester.BinaryAutomation.assert_exploit(exploit=failed_exploit, flag="cueh{", flag_path="/flag")
    assert not tester.BinaryAutomation.assert_exploit(exploit=failed_exploit, remote=True)
    #
    with pytest.raises(TypeError) as e_info:
        tester.BinaryAutomation.assert_exploit(exploit="", flag="cueh{", flag_path="/flag")

    with pytest.raises(ValueError) as e_info:
        tester.BinaryAutomation.assert_exploit(exploit=bad_exploit, flag="cueh{", flag_path="/flag")
    assert tester.BinaryAutomation.assert_exploit(exploit=exploit_shell, remote=True)


@pytest.mark.parametrize("sym", [
    ("main", True),
    ("puts", True),
    (1, False),
    ("", False),
    ("not_a_symbol", False),
])
def test_assert_symbol_exists(sym: str):
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
def test_assert_protections(lst):
    assert tester.BinaryAutomation.assert_protections(lst[0]) == lst[1]


def test_assert_rop_gadget_exists():
    assert tester.BinaryAutomation.assert_rop_gadget_exists(["ret"])

    # pwntools does not do JOP
    assert not tester.BinaryAutomation.assert_rop_gadget_exists(["jmp rax"])
    assert tester.BinaryAutomation.assert_rop_gadget_exists(["jmp rax"], deep_search=True)


def test_assert_string_exists():
    assert tester.BinaryAutomation.assert_string_exists("main")  # symbol
    assert tester.BinaryAutomation.assert_string_exists("/flag")  # data
    assert not tester.BinaryAutomation.assert_string_exists("FOOBAR")  # not in binary

