"""
GDB Python API bridge.
This code from pwntools licensed under MIT.
https://github.com/Gallopsled/pwntools/blob/c45e92d78b3fc6ecf0a3b839417bbaee2e54637c/pwnlib/gdb_api_bridge.py
"""

# Copyright (c) 2015 Gallopsled et al.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,nano
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import gdb

import socket
from threading import Condition
import time

from rpyc.core.protocol import Connection
from rpyc.core.service import Service
from rpyc.lib import spawn
from rpyc.lib.compat import select_error
from rpyc.utils.server import ThreadedServer


class ServeResult:
    """Result of serving requests on GDB thread."""
    def __init__(self):
        self.cv = Condition()
        self.done = False
        self.exc = None

    def set(self, exc):
        with self.cv:
            self.done = True
            self.exc = exc
            self.cv.notify()

    def wait(self):
        with self.cv:
            while not self.done:
                self.cv.wait()
            if self.exc is not None:
                raise self.exc


class GdbConnection(Connection):
    """A Connection implementation that serves requests on GDB thread.

    Serving on GDB thread might not be ideal from the responsiveness
    perspective, however, it is simple and reliable.
    """
    SERVE_TIME = 0.1  # Number of seconds to serve.
    IDLE_TIME = 0.1  # Number of seconds to wait after serving.

    def serve_gdb_thread(self, serve_result):
        """Serve requests on GDB thread."""
        try:
            deadline = time.time() + self.SERVE_TIME
            while True:
                timeout = deadline - time.time()
                if timeout < 0:
                    break
                super().serve(timeout=timeout)
        except Exception as exc:
            serve_result.set(exc)
        else:
            serve_result.set(None)

    def serve_all(self):
        """Modified version of rpyc.core.protocol.Connection.serve_all."""
        try:
            while not self.closed:
                serve_result = ServeResult()
                gdb.post_event(lambda: self.serve_gdb_thread(serve_result))
                serve_result.wait()
                time.sleep(self.IDLE_TIME)
        except (socket.error, select_error, IOError):
            if not self.closed:
                raise
        except EOFError:
            pass
        finally:
            self.close()


class GdbService(Service):
    """A public interface for Pwntools."""

    _protocol = GdbConnection  # Connection subclass.
    exposed_gdb = gdb  # ``gdb`` module.

    def exposed_set_breakpoint(self, client, has_stop, *args, **kwargs):
        """Create a breakpoint and connect it with the client-side mirror."""
        if has_stop:
            class Breakpoint(gdb.Breakpoint):
                def stop(self):
                    return client.stop()

            return Breakpoint(*args, **kwargs)
        return gdb.Breakpoint(*args, **kwargs)

    def exposed_set_finish_breakpoint(self, client, has_stop, has_out_of_scope, *args, **kwargs):
        """Create a finish breakpoint and connect it with the client-side mirror."""
        class FinishBreakpoint(gdb.FinishBreakpoint):
            if has_stop:
                def stop(self):
                    return client.stop()
            if has_out_of_scope:
                def out_of_scope(self):
                    client.out_of_scope()
        return FinishBreakpoint(*args, **kwargs)

    def exposed_quit(self):
        """Terminate GDB."""
        gdb.post_event(lambda: gdb.execute('quit'))


spawn(ThreadedServer(
    service=GdbService(),
    socket_path=socket_path,
    protocol_config={
        'allow_all_attrs': True,
    },
).start)
