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


def test_assert_redirect():
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


def test_assert_page_not_found():
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
    assert b"FOOBAR" in shell.recvline()
    shell.close()


# TODO: Uncomment or add fixture so it doesnt take 5 seconds
# def test_fail_reverse_shell():
#     def exploit_code_fail(p1,p2,p3,p4):
#         return False
#     shell = tester.run_reverse_shell_exploit(lhost, lport, exploit_code_fail)
#     assert not shell


def test_set_target():
    tester.WebAutomation.reset_session()
    tester.WebAutomation.base_url = None
    tester.WebAutomation.set_target(f"http://{rhost}:{rport}")
    assert tester.WebAutomation.base_url == f"http://{rhost}:{rport}"


def test_get_and_reset_session():
    tester.WebAutomation.reset_session()
    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/",
                 data={"username": "pwntest", "password": "foobar"})
    assert session.cookies
    tester.WebAutomation.reset_session()
    assert not tester.WebAutomation.get_session().cookies


@pytest.mark.parametrize("url", [
    f"http://{rhost}:{rport}",
    f"https://{rhost}:{rport}"
])
def test_is_full_url(url):
    assert tester.WebAutomation.is_full_url(url)


@pytest.mark.parametrize("url", [
    f"{rhost}:{rport}",
    f"http:/{rhost}:{rport}",
    f"htp://{rhost}:{rport}",
    f"https:/{rhost}:{rport}",
    f"tcp:/{rhost}:{rport}",
])
def test_is_not_full_url(url):
    assert not tester.WebAutomation.is_full_url(url)


def test_url_join():
    assert tester.WebAutomation.urljoin(f"http://{rhost}:{rport}",
                                        "/") == f"http://{rhost}:{rport}/"
    assert tester.WebAutomation.urljoin(f"http://{rhost}:{rport}",
                                        "/target", "foobar", "/barfoo/") == f"http://{rhost}:{rport}/target/foobar/barfoo"
    assert tester.WebAutomation.urljoin(f"http://{rhost}:{rport}",
                                        "/target/foobar/barfoo") == f"http://{rhost}:{rport}/target/foobar/barfoo"


def test_make_full_url():
    tester.WebAutomation.set_target(f"http://{rhost}:{rport}")
    assert tester.WebAutomation.make_full_url("/target/foobar/barfoo") == f"http://{rhost}:{rport}/target/foobar/barfoo"


@pytest.mark.parametrize("url", [
    (f"http://{rhost}:{rport}/", "/"),
    (f"http://{rhost}:{rport}/target/foobar/barfoo",
     "/target/foobar/barfoo"),
    (f"http://{rhost}:{rport}/target/foobar/barfoo/",
     "/target/foobar/barfoo/"),
    (f"http://{rhost}:{rport}/target/foobar/barfoo?foo=bar&bar=foo",
     "/target/foobar/barfoo"),
    (f"https://{rhost}:{rport}/target/foobar/barfoo?foo=bar&bar=foo",
     "/target/foobar/barfoo"),
])
def test_strip_url_path(url):
    assert tester.WebAutomation.strip_url_path(url[0]) == url[1]


def test_assert_string_on_page():
    tester.WebAutomation.reset_session()
    assert tester.WebAutomation.assert_string_on_page(
        f"http://{rhost}:{rport}", "Not logged in")
    assert not tester.WebAutomation.assert_string_on_page(
        f"http://{rhost}:{rport}", "Logged in")

    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/",
                 data={"username": "pwntest", "password": "foobar"})
    assert tester.WebAutomation.assert_string_on_page(f"http://{rhost}:{rport}",
                                                      "Logged in",
                                                      session=True)
    assert tester.WebAutomation.assert_string_on_page(f"http://{rhost}:{rport}",
                                                      "Not logged in",
                                                      session=False)


def test_get_element_contents_by_id():
    assert not tester.WebAutomation.get_element_contents_by_id(
        "/", "message", session=True) == "Logged in"

    assert tester.WebAutomation.get_element_contents_by_id(
        "/", "FOOBAR", session=True) == "Logged in"
