import requests
from urllib3.util.url import parse_url

from bs4 import BeautifulSoup

import pwnlib.log
import pwnlib.tubes


class WebAutomation:

    def __init__(self, rhost: str, rport: int, lhost: str, lport: int) -> None:
        self.base_url = None
        self.log = pwnlib.log.getLogger("pwntest")
        self.timeout: int = 2
        self.remote_ip: str = rhost
        self.remote_port: int = rport
        self.local_host: str = lhost
        self.local_port: int = lport
        self.https: bool = False
        self.session: requests.sessions.Session = requests.session()

    def set_target(self, base_url: str) -> None:
        """
        Set a base target for the testing. This is useful if the all the testing runs on a specific vhost or something

        Parameters:
            base_url: Base URL to use for testing
        """
        self.base_url = base_url

    @staticmethod
    def is_full_url(self, text) -> bool:
        """
        Check if a string is a full URL

        Parameters:
            text: String to check

        Returns:
            True if string is a full URL, False otherwise.
        """

        # TODO: see if there is a better way to do this
        if text.startswith("http://") or text.startswith("https://"):
            return True
        return False

    @staticmethod
    def strip_url_path(url) -> str:
        """
        Strip the path from a full url

        :param url:
        :return:
        """
        return parse_url(url).path

    def assert_string_on_page(self, url: str, string: str) -> bool:
        """
        Check if a string is on a page.

        :param url: URL to check
        :param string: String to check for
        :return: True if string is on page, False otherwise.
        """
        passed: bool = False

        try:
            response: requests.models.Response = self.session.get(url, timeout=self.timeout)
            if string not in response.text:
                self.log.debug(f"Could not find string '{string}' on page: {url}")
            else:
                self.log.debug(f"String '{string}' found on page: {url}")
                passed = True
        except requests.exceptions.Timeout:
            self.log.warning("Request timed out.")

        return passed

    def assert_redirect(self, url, session: bool = False):
        """
        Returns true if the response to the request is a redirect

        :param session:
        :param url:
        :return:
        """
        r = self.session if session else requests
        response = r.get(url)

        # if there were any janky methods of redirecting, they should be caught by the history tracking
        return response.is_redirect and len(response.history) == 0

    def assert_page_not_found(self, request_method, url: str) -> bool:
        if not callable(request_method):
            raise TypeError("'request_method' must be callable")

        if not self.is_full_url(url):
            if self.base_url is None:
                self.log.error("Base URL not set. Please set a base URL with set_target() or pass a full URL")
                return False
            else:
                self.log.debug(f"URL '{url}' is not a full URL. Joining with base URL: {self.base_url}")
                url = parse_url(self.base_url).join(url)

        response = request_method(url)
        return response.status_code == 404

    def assert_get_page_not_found(self, pages: list, session: bool = False) -> bool:
        """
        Assert that a given page returns a 404 status code from a get request. By default, this is from a new session.
        If session is true then from the internal session object

        :param pages: The page to send a GET request to
        :param session: If session is true then request using the internal session object
        :return: True if the page returns a 404 status code, False otherwise
        """

        r = self.session if session else requests

        if not isinstance(pages, list):
            # some people just dont read docs...
            # but might as well fix the small mistakes ourselves
            if isinstance(pages, str):
                pages = [pages]
            else:
                self.log.error("Invalid type for parameter 'pages'")
                return False

        for page in pages:
            if not self.assert_page_not_found(r.get, page):
                return False

        return True

    def assert_post_page_not_found(self, pages: list, session: bool = False):
        """
        Assert that a given page returns a 404 status code from a post request. By default, this is from a new session.

        :param pages: The page to send a POST request to
        :param session: If session is true then from the internal session object
        :return:
        """

        r = self.session if session else requests

        if not isinstance(pages, list):
            # some people just dont read docs...
            # but might as well fix the small mistakes ourselves
            if isinstance(pages, str):
                pages = [pages]
            else:
                self.log.error("Invalid type for parameter 'pages'")
                return False

        for page in pages:
            if not self.assert_page_not_found(r.post, page):
                return False

        return True

    def assert_page_codes(self, pages: dict, session: bool = False):
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

        for req in pages.keys():
            match req["type"]:
                case "POST":
                    response = r.post(url=req)
                case "GET":
                    response = r.get(url=req)
                case _:
                    self.log.warning(f"Request type '{req['type']}' not supported. Returning False")
                    return False

            if response.status_code == req["status_code"]:
                return False

        return True

    def get_element_contents_by_id(self, url: str, element: str) -> str:
        """
        Get the contents of an element on a page. Only the first element of a page will be returned, as
        HTML specification states that IDs should be unique anyway.

        :param url: URL to check
        :param element: Element to get contents of
        :return: Contents of element.
        """
        element_data: str = ""
        try:
            response: requests.models.Response = self.session.get(url, timeout=self.timeout)
            soup: BeautifulSoup = BeautifulSoup(response.text, 'html.parser')
            element_data = soup.find(id=element).text
        except requests.exceptions.Timeout:
            self.log.warning("Request timed out.")
        return element_data
