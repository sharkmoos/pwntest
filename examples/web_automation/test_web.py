import sys
import pytest
import os

sys.path.append(os.getcwd())
import pwntest

from examples.web_automation.exploit import main as exploit_code

rhost, rport = "127.0.0.1", 9004
lhost, lport = "host.docker.internal", 4444
tester = pwntest.PwnTest(remote_target=rhost, port=rport)


def assert_partial_path():
    assert tester.WebAutomation.assert_page_codes({"/": 200, "/hidden": 404})


def test_redirect():
    tester.WebAutomation.reset_session()
    tester.WebAutomation.set_target(f"http://{rhost}:{rport}")
    assert tester.WebAutomation.assert_redirect("http://127.0.0.1:9004/profile")
    assert tester.WebAutomation.assert_redirect("/profile")

    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/", data={"username": "pwntest", "password": "foobar"})
    assert not tester.WebAutomation.assert_redirect("http://127.0.0.1:9004/profile", session=True)
    assert not tester.WebAutomation.assert_redirect("/profile", session=True)
    assert tester.WebAutomation.assert_redirect("/profile", session=False)
    assert tester.WebAutomation.get_element_contents_by_id("/", "message", session=False) == "Not logged in"
    assert tester.WebAutomation.get_element_contents_by_id("/", "message", session=True) == "Logged in"


def test_page_404():
    tester.WebAutomation.reset_session()
    assert tester.WebAutomation.assert_get_page_not_found("http://127.0.0.1:9004/hidden")

    assert tester.WebAutomation.assert_get_page_not_found("http://127.0.0.1:9004/hidden", session=True)

    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/", data={"username": "pwntest", "password": "foobar"})
    assert not tester.WebAutomation.assert_get_page_not_found("http://127.0.0.1:9004/hidden", session=True)

    assert tester.WebAutomation.assert_string_on_page("http://127.0.0.1:9004/hidden", "Well done", session=True)


def test_reverse_shell():
    shell = tester.run_reverse_shell_exploit(lhost, lport, exploit_code)
    if not shell:
        pytest.fail("Failed to get reverse shell")
    shell.sendline(b"echo FOOBAR")
    assert shell.recvline().strip() == b"FOOBAR"
    shell.close()


def test_fail_reverse_shell():
    def exploit_code_fail(p1,p2,p3,p4):
        return False
    shell = tester.run_reverse_shell_exploit(lhost, lport, exploit_code_fail)
    assert shell
    shell.sendline(b"echo FOOBAR")
    assert shell.recvline().strip() == b"FOOBAR"
    shell.close()
