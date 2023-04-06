import sys
import pytest
import os
import requests
from unittest.mock import patch

sys.path.append(os.getcwd())
import pwntest

from examples.web_automation.exploit import main as exploit_code

rhost, rport = "127.0.0.1", 9004
lhost, lport = "host.docker.internal", 4444
tester = pwntest.PwnTest(remote_target=rhost, port=rport)


@pytest.mark.example
def test_assert_redirect():
    tester.WebAutomation.reset_session()
    assert tester.WebAutomation.assert_redirect("http://127.0.0.1:9004/profile")
    tester.WebAutomation.set_target(f"http://{rhost}:{rport}")
    assert tester.WebAutomation.assert_redirect("/profile")


@pytest.mark.example
def test_assert_page_not_found():
    tester.WebAutomation.reset_session()
    assert not tester.WebAutomation.assert_post_page_not_found("http://127.0.0.1:9004/profile")
    assert tester.WebAutomation.assert_get_page_not_found("http://127.0.0.1:9004/hidden", session=True)
    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/", data={"username": "pwntest", "password": "foobar"})
    assert not tester.WebAutomation.assert_get_page_not_found("/hidden", session=True)


@pytest.mark.example
def test_reverse_shell():
    shell = tester.run_reverse_shell_exploit(lhost, lport, exploit_code, remote_host=rhost, remote_port=rport)
    assert shell
    shell.close()


@pytest.mark.example
def test_assert_string_on_page():
    tester.WebAutomation.reset_session()
    assert tester.WebAutomation.assert_string_on_page(
        f"http://{rhost}:{rport}", "Not logged in")

    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/",
                 data={"username": "pwntest", "password": "foobar"})
    assert tester.WebAutomation.assert_string_on_page(f"http://{rhost}:{rport}",
                                                      "Logged in",
                                                      session=True)


@pytest.mark.example
def test_get_element_contents_by_id():
    tester.WebAutomation.reset_session()
    assert not tester.WebAutomation.get_element_contents_by_id(
        "/", "message", session=True) == "Logged in"

    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/",
                 data={"username": "pwntest", "password": "foobar"})
    assert tester.WebAutomation.get_element_contents_by_id(
        "/", "message", session=True) == "Logged in"


@pytest.mark.example
def test_assert_page_codes():
    tester.WebAutomation.reset_session()
    assert tester.WebAutomation.assert_page_codes({
        f"http://{rhost}:{rport}": {"type": "get", "status_code": 200},
        "http://127.0.0.1:9004/profile": {"type": "get", "status_code": 302},
        "http://127.0.0.1:9004/FOOBAR": {"type": "post", "status_code": 404},
        "/": {"type": "get", "status_code": 200},
    }, session=False)


# ============== UNIT TESTS NOT EXAMPLE ==============

def test_unit_assert_redirect():
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


def test_unit_assert_page_not_found():
    tester.WebAutomation.reset_session()
    assert not tester.WebAutomation.assert_post_page_not_found("http://127.0.0.1:9004/profile")
    assert not tester.WebAutomation.assert_post_page_not_found("/profile")
    assert tester.WebAutomation.assert_get_page_not_found("http://127.0.0.1:9004/hidden")
    assert tester.WebAutomation.assert_get_page_not_found("http://127.0.0.1:9004/hidden", session=True)
    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/", data={"username": "pwntest", "password": "foobar"})
    assert not tester.WebAutomation.assert_get_page_not_found("/hidden", session=True)

    # a user should not do this
    assert tester.WebAutomation._assert_page_not_found(requests.get, "/hidden")
    with pytest.raises(TypeError):
        tester.WebAutomation._assert_page_not_found("", "http://127.0.0.1:9004/hidden")

    with pytest.raises(TypeError):
        tester.WebAutomation._assert_page_not_found(requests.get, b"http://127.0.0.1:9004/hidden")

    with pytest.raises(TypeError):
        tester.WebAutomation._assert_page_not_found(requests.get, b"/hidden")


def test_fail_reverse_shell():
    def exploit_code_fail(p1, p2, p3, p4):
        return False

    shell = tester.run_reverse_shell_exploit(lhost, lport, exploit_code_fail, timeout=1, p3="", p4="")
    assert not shell


def test_unit_set_target():
    tester.WebAutomation.reset_session()
    tester.WebAutomation.base_url = None
    tester.WebAutomation.set_target(f"http://{rhost}:{rport}")
    assert tester.WebAutomation.base_url == f"http://{rhost}:{rport}"


def test_unit_get_and_reset_session():
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
    with pytest.raises(TypeError):
        assert tester.WebAutomation.urljoin(f"http://{rhost}:{rport}",
                                            b"/target/foobar/barfoo") == f"http://{rhost}:{rport}/target/foobar/barfoo"


def test_make_full_url():
    tester.WebAutomation.base_url = None
    with pytest.raises(ValueError):
        assert tester.WebAutomation.make_full_url("/target/foobar/barfoo") == f"http://{rhost}:{rport}/target/foobar/barfoo"
    tester.WebAutomation.set_target(f"http://{rhost}:{rport}")
    assert tester.WebAutomation.make_full_url("/target/foobar/barfoo") == f"http://{rhost}:{rport}/target/foobar/barfoo"
    assert tester.WebAutomation.make_full_url(f"http://{rhost}:{rport}/target/foobar/barfoo") == f"http://{rhost}:{rport}/target/foobar/barfoo"


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


def test_unit_assert_string_on_page():
    tester.WebAutomation.reset_session()
    assert tester.WebAutomation.assert_string_on_page(
        f"http://{rhost}:{rport}", "Not logged in")

    assert tester.WebAutomation.assert_string_on_page(
        "/", "Not logged in")
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


@patch('pwntest.modules.web.requests.get')
def test_assert_string_on_page_timeout(mock_requests):
    mock_requests.side_effect = requests.exceptions.ConnectionError()
    assert not tester.WebAutomation.assert_string_on_page("http://www.google.com:81/", "Logged in", session=False)


def test_unit_get_element_contents_by_id():
    tester.WebAutomation.reset_session()
    assert not tester.WebAutomation.get_element_contents_by_id(
        "/", "message", session=True) == "Logged in"

    session = tester.WebAutomation.get_session()
    session.post("http://127.0.0.1:9004/",
                 data={"username": "pwntest", "password": "foobar"})
    assert tester.WebAutomation.get_element_contents_by_id(
        "/", "message", session=True) == "Logged in"

    assert not tester.WebAutomation.get_element_contents_by_id(
        "/", "FOOBAR", session=True) == "Logged in"

    with pytest.raises(TypeError):
        assert not tester.WebAutomation.get_element_contents_by_id(
            b"/", "FOOBAR", session=True) == "Logged in"

    assert not tester.WebAutomation.get_element_contents_by_id(
        "/FOOBAR", "FOOBAR", session=True, allow_redirects=False) == "Logged in"


@patch('pwntest.modules.web.requests.get')
def test_get_element_contents_by_id_timeout(mock_requests):
    mock_requests.side_effect = requests.exceptions.ConnectionError()
    assert not tester.WebAutomation.get_element_contents_by_id(
        "/FOOBAR", "FOOBAR", session=False) == "Logged in"


def test_unit_assert_page_codes():
    tester.WebAutomation.reset_session()
    assert tester.WebAutomation.assert_page_codes({
        f"http://{rhost}:{rport}": {"type": "get", "status_code": 200},
        "http://127.0.0.1:9004/profile": {"type": "get", "status_code": 302},
        "http://127.0.0.1:9004/FOOBAR": {"type": "post", "status_code": 404},
        "/": {"type": "get", "status_code": 200},
    }, session=False)

    assert not tester.WebAutomation.assert_page_codes({
        f"http://{rhost}:{rport}": {"type": "put", "status_code": 200},
    }, session=False)

    assert not tester.WebAutomation.assert_page_codes({
        f"http://{rhost}:{rport}": {"type": "get", "status_code": 201},
    }, session=False)

    with pytest.raises(TypeError):
        tester.WebAutomation.assert_page_codes({
            f"http://{rhost}:{rport}": {"type": b"get", "status_code": 200},
        })

    with pytest.raises(TypeError):
        tester.WebAutomation.assert_page_codes({
            f"http://{rhost}:{rport}": {"type": "get", "status_code": "200"},
        })
