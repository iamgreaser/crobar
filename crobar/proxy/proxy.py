from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from threading import Thread
from typing import Tuple
from typing import Optional
# from crobar.api import HackingOpException

"""
Creates a simple single-connection proxy server that listens to localhost on a free port, and
forwards it to the provided destination

You should redirect sockets you're interested in to this proxy - make sure to get the proper local
port before starting it

Uses smaller helper classes to properly thread two-way communications
"""


class Proxy(Thread):
    __slots__ = (
        "_ltp",
        "_ptr"
    )

    def __init__(self, ip_addr: str, port: int) -> None:
        Thread.__init__(self)
        self.daemon = True

        self._ltp: _LocalToProxy = _LocalToProxy(ip_addr, port)
        self._ptr: _ProxyToRemote = _ProxyToRemote(ip_addr, port)

        self._ltp.source = self._ptr.dest
        self._ptr.source = self._ptr.dest

    def get_port(self) -> int:
        return self._ltp.local_port

    def run(self) -> None:
        self._ltp.start()
        self._ptr.start()


class _ProxyPart(Thread):
    __slots__ = (
        "ip_addr",
        "port",
        "listener",
        "local_port"
        "source",
        "dest",
    )

    def __init__(self, ip_addr: str, port: int) -> None:
        Thread.__init__(self)
        self.daemon = True

        self.ip_addr: str = ip_addr
        self.port: int = port

        self.listener: socket = socket(AF_INET, SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.local_port: int = self.listener.getsockname()[1]

        self.source: Optional[socket] = None
        self.dest: Optional[socket] = None

    def __del__(self) -> None:
        print(f"Deleting {self!r}")
        self.listener.close()
        if self.source is not None:
            self.source.close()
        if self.dest is not None:
            self.dest.close()

    def run(self) -> None:
        if self.source is None or self.dest is None:
            # raise HackingOpException("Tried to start proxy without setting source/destination")
            return

        while True:
            data: bytes = self.source.recv(4096)

            if not data:
                continue

            print("Send: " + data.hex())

            self.dest.sendall(data)


# Which part it is only changes if the first connection is source or destination
class _LocalToProxy(_ProxyPart):
    def run(self) -> None:
        self.listener.listen()
        conn: Tuple[socket, int] = self.listener.accept()
        self.source: socket = conn[0]

        print(f"Accepted connection from {conn[1]}:{self.source.getsockname()[1]}")

        _ProxyPart.run(self)


class _ProxyToRemote(_ProxyPart):
    def run(self) -> None:
        self.listener.listen()
        conn: Tuple[socket, int] = self.listener.accept()
        self.dest: socket = conn[0]

        print(f"Accepted connection from {conn[1]}:{self.dest.getsockname()[1]}")

        _ProxyPart.run(self)


if __name__ == "__main__":
    # tcpbin.org
    p = Proxy("52.20.16.20", 40000)
    print(f"Local port: {p.get_port()}")
    p.start()

    while True:
        pass
