"""Exits 0 when the Modbus TCP server accepts connections."""

import socket

socket.create_connection(("127.0.0.1", 5020), 2).close()
