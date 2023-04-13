"""
The web module is all about interacting with web applications.

This module can be initialised either directly, or by using the base PwnTest class.
The decision is left up to the user, we would recommend using the base PwnTest class
if functionality from other modules or the base pwntest class is required.

**Method 1**


>>> import pwntest
>>> tester = pwntest.PwnTest(remote_target="example.com", port=80)

**Method 2**

>>> import pwntest
>>> tester = pwntest.modules.web.WebAutomation(remote_target="example.com", port=80)


----------------------------
"""

import requests
from urllib3.util.url import parse_url
from bs4 import BeautifulSoup

import pwnlib.log
import pwnlib.tubes


class WebAutomation:
    """
    WebAutomation class for automating web application testing.
    """

    def __init__(self, rhost: str, rport: int) -> None:
        """
        Initialise the WebAutomation class. Inherits the relevant PwnTestBase attributes.

        :param rhost: The target IP address
        :param rport: The target port
        """

        self.log = pwnlib.log.getLogger("pwntest")
        self.base_url = None
        self.timeout: int = 2
        self.remote_ip: str = rhost
        self.remote_port: int = rport
        self.session: requests.sessions.Session = requests.session()

    def set_target(self, base_url: str) -> None:
        """
        Set a base target for the testing. This is useful if the all the testing runs on a specific vhost or something.
        Currently, this is not done automatically as it would be difficult to decide on a sensible default.

        Parameters:
            base_url: Base URL to use for testing

        **Example:**

        >>> import pwntest
        >>> tester = pwntest.PwnTest(remote_target="example.com", port=80)
        >>> tester.WebAutomation.base_url
        None
        >>> tester.WebAutomation.set_target("http://example.com")
        >>> tester.WebAutomation.base_url
        'http://example.com'
        """
        self.base_url = base_url

    def get_session(self) -> requests.sessions.Session:
        """
        Get the current session object

        :return: Current session object
        """
        return self.session

    @staticmethod
    def is_full_url(url: str) -> bool:
        """
        Check if a string is a full URL

        Parameters:
            text: String to check

        Returns:
            True if string is a full URL, False otherwise.
        """

        if not isinstance(url, str):
            raise TypeError(f"is_full_url argument 'url' must be str, not '{url}'")

        # TODO: see if there is a better way to do this
        if url.startswith("http://") or url.startswith("https://"):
            return True
        return False

    @staticmethod
    def urljoin(*args):
        """
        Join a list of strings into a URL
        :param args: List of strings to join into url
        :return: Joined url
        """
        for arg in args:
            if isinstance(arg, str):
                continue
            raise TypeError(f"urljoin arguments must be str, not '{arg}'")

        # TODO: see if there is a better way to do this
        #   not super keen to import urlparse just for this
        #   like the stackoverflow suggests
        # return "/".join(map(lambda x: x.strip('/'), args))
        return "/".join(part.strip("/") for part in args)

    def make_full_url(self, path) -> str:
        """
        Make a full URL from a path. If the url is already a full url then return the url

        :param path: Path to join with the base url
        :return: Base joined with the path
        """
        if self.is_full_url(path):
            return path
        if self.base_url is None:
            raise ValueError("Base URL not set. Please set a base URL with set_target() or pass a full URL")

        return self.urljoin(self.base_url, path)

    @staticmethod
    def strip_url_path(url) -> str:
        """
        Strip the path from a full url

        :param url: URL to strip
        :return: Just the url path, without the base
        """
        return parse_url(url).path

    def reset_session(self) -> requests.sessions.Session:
        """
        Reset the session object
        :return: New session object
        """
        self.session = requests.session()
        return self.session

    def assert_string_on_page(self, url: str, string: str, session: bool = True) -> bool:
        """
        Check if a string is on a page.

        :param url: URL to check
        :param string: String to check for
        :return: True if string is on page, False otherwise.
        :param session: If session is true then request using the internal session object
        """
        try:
            r = self.session if session else requests
            if not self.is_full_url(url):
                url = self.make_full_url(url)
            response: requests.models.Response = r.get(url, timeout=self.timeout)
            return string in response.text
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as e:
            self.log.warning(f'Error connecting: %s', e)

        return False

    def assert_redirect(self, url, session: bool = True) -> bool:
        """
        Returns true if the response to the request is a redirect

        :param session:
        :param url:
        :return:
        """

        r = self.session if session else requests

        if not self.is_full_url(url):
            url = self.make_full_url(url)

        response = r.get(url)

        # if there were any janky methods of redirecting,
        # they should be caught by the history tracking
        return response.is_redirect or len(response.history) != 0

    def _assert_page_not_found(self, request_method, url: str) -> bool:
        if not callable(request_method):
            raise TypeError("'request_method' must be callable")

        if not self.is_full_url(url):
            url: str = self.make_full_url(url)

        response = request_method(url)
        return response.status_code == 404

    def assert_get_page_not_found(self, page: str, session: bool = True) -> bool:
        """
        Assert that a given page returns a 404 status code from a get request.
        By default, this is from a new session.
        If session is true then from the internal session object

        :param page: The page to send a GET request to
        :param session: If session is true then request using the internal session object
        :return: True if the page returns a 404 status code, False otherwise
        """
        r = self.session if session else requests

        if not self.is_full_url(page):
            page = self.make_full_url(page)

        return self._assert_page_not_found(r.get, page)

    def assert_post_page_not_found(self, page: str, session: bool = True):
        """
        Assert that a given page returns a 404 status code from a post request.
        By default, this is from a new session.

        :param page: The page to send a POST request to
        :param session: If session is true then from the internal session object
        :return:
        """
        r = self.session if session else requests

        if not self.is_full_url(page):
            page = self.make_full_url(page)

        return self._assert_page_not_found(r.post, page)

    def assert_page_codes(self, pages: dict, allow_redirects=False, session: bool = True):
        """
        Pass a dictionary of dictionaries of the format

        .. code-block:: python

            pages = {
                url: {
                    "status_code": 200
                    "type": "POST"
                }
            }

        :return:
        """
        r = self.session if session else requests

        for page in pages:
            url = page
            page = pages[page]
            if not isinstance(page["status_code"], int):
                raise TypeError(f"Invalid type '{type(page['status_code'])}' for parameter 'status_code'")
            if not isinstance(page["type"], str):
                raise TypeError(f"Invalid type '{type(page['type'])}' for parameter 'type'")
            if not self.is_full_url(url):
                url = self.make_full_url(url)
            match page["type"].upper():
                case "POST" | "post":
                    response = r.post(url=url, allow_redirects=allow_redirects)
                case "GET" | "get":
                    response = r.get(url=url, allow_redirects=allow_redirects)
                case _:
                    self.log.warning(f"Request type '{page['type']}' not supported. Returning False")
                    return False
            if response.status_code != page["status_code"]:
                self.log.info("Page %s returned status code %s, expected %s", url, response.status_code, page["status_code"])
                return False
        return True

    def get_element_contents_by_id(self, url: str, element: str, allow_redirects=True, session: bool = True) -> str:
        """
        Get the contents of an element on a page. Only the first element of a page will be returned, as
        HTML specification states that IDs should be unique anyway.

        :param allow_redirects:
        :param session:
        :param url: URL to check
        :param element: Element to get contents of
        :return: Contents of element.
        """

        r = self.session if session else requests
        try:
            if not self.is_full_url(url):
                url = self.make_full_url(url)
            response: requests.models.Response = r.get(url, timeout=self.timeout, allow_redirects=allow_redirects)
            if response.status_code != 200:
                return ""
            soup: BeautifulSoup = BeautifulSoup(response.text, 'html.parser')
            element_data = soup.find(id=element)
            if not element_data:
                self.log.info(f"Element '{element}' not found on page '{url}'")
                return ""

        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as e:
            self.log.warning(f'Error connecting: %s', e)
            return ""

        return element_data.text
