import threading
import time
import signal

import pwnlib.log
import pwnlib.tubes

from pwntest.modules import general


class WebAutomation:
    def __init__(self, rhost: str, rport: int, lhost: str, lport: int) -> None:
        self.timeout: float = 5.0
        self.remote_ip: str = rhost
        self.remote_port: int = rport
        self.local_host: str = lhost
        self.local_port: int = lport

        self.log_level: str = "WARNING"
        self.log = pwnlib.log.getLogger("pwntest::WebAutomation")

