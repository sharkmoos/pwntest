import pwn
import threading
import time
import signal

from pwntest.modules import general


class WebAutomation:
    def __init__(self, rhost: str, rport: int, lhost: str, lport: int) -> None:
        self.timeout: float = 5.0
        self.remote_ip: str = rhost
        self.remote_port: int = rport
        self.local_host: str = lhost
        self.local_port: int = lport
        self.log_level: str = "WARNING"

    def run_web_exploit(self, exploit_function) -> pwn.tubes.listen.listen or None:
        if not exploit_function:
            raise ValueError("Exploit function not provided")
        socket_details: dict = {}

        # create a listener and run it in a new thread
        listener_thread = threading.Thread(target=general.run_socket_listener, args=(self.local_host, self.local_port, socket_details, self.timeout))
        listener_thread.start()

        exploit_function(self.remote_ip, self.remote_port, self.local_host, self.local_port)

        listener_thread.join()  # wait for the listener to finish or timeout
        if socket_details:  # if there are details, a connection was made
            conn = pwn.remote(
                socket_details["host"],
                socket_details["port"],
                fam=socket_details["fam"],
                typ=socket_details["type"],
                sock=socket_details["conn"]
            )
            pwn.log.success("Upgraded to full pwntools connection")
        else:
            pwn.log.warning("Could not establish a connection to the remote host")
            conn = None

        return conn
