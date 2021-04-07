'''
Implement HTTP/3 proxy behavior in Python.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import asyncio
import importlib
import logging
import os
from pathlib import Path
import time
from collections import deque
from email.utils import formatdate
from typing import Callable, Deque, Dict, List, Optional, Union, cast

import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, Headers, HeadersReceived
from aioquic.h3.exceptions import NoAvailablePushIDError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger, QuicLoggerTrace
from aioquic.quic.events import DatagramFrameReceived, ProtocolNegotiated, QuicEvent
from aioquic.tls import SessionTicket

AsgiApplication = Callable
HttpConnection = Union[H0Connection, H3Connection]

SERVER_NAME = "aioquic/" + aioquic.__version__


class QuicDirectoryLogger(QuicLogger):
    """
    Custom QUIC logger which writes one trace per file.
    """

    def __init__(self, path: str) -> None:
        if not os.path.isdir(path):
            raise ValueError("QUIC log output directory '%s' does not exist" % path)
        self.path = path
        super().__init__()

    def end_trace(self, trace: QuicLoggerTrace) -> None:
        trace_dict = trace.to_dict()
        trace_path = os.path.join(
            self.path, trace_dict["common_fields"]["ODCID"] + ".qlog"
        )
        with open(trace_path, "w") as logger_fp:
            json.dump({"qlog_version": "draft-01", "traces": [trace_dict]}, logger_fp)
        self._traces.remove(trace)


class HttpRequestHandler:
    def __init__(
        self,
        *,
        authority: bytes,
        connection: HttpConnection,
        protocol: QuicConnectionProtocol,
        scope: Dict,
        stream_ended: bool,
        stream_id: int,
        transmit: Callable[[], None],
    ) -> None:
        self.authority = authority
        self.connection = connection
        self.protocol = protocol
        self.queue: asyncio.Queue[Dict] = asyncio.Queue()
        self.scope = scope
        self.stream_id = stream_id
        self.transmit = transmit

        self.request_done_event: asyncio.Event = asyncio.Event()
        self.request_headers: Headers = None
        self.request_body = b''

        self.response_headers: Headers
        self.response_body = b""

        if stream_ended:
            self.queue.put_nowait({"type": "http.request"})

    def http_event_received(self, event: H3Event) -> None:
        print("HttpRequestHandler: handling HTTP event")
        if isinstance(event, DataReceived):
            self.request_body += event.data
            if event.stream_ended:
                print("Setting request_done_event")
                self.request_done_event.set()
        elif isinstance(event, HeadersReceived):
            if self.request_headers is not None:
                self.request_headers.append(event.headers)
            else:
                self.request_headers = event.headers
            if event.stream_ended:
                print("Setting request_done_event")
                self.request_done_event.set()
        self.transmit()

    async def send_response(self) -> None:
        print("Awaiting on request_done_event")
        await self.request_done_event.wait()
        print("request_done_event set!!!")

        # TODO: These will be propulated from the server's response eventually.
        print("Sending a response (supposedly).")
        self.response_headers = [
            (b':status', b'200'),
            (b'x-response-header', b'1')]
        self.response_body = b'Some great body'
        # End TODO

        self.connection.send_headers(
            stream_id=self.stream_id,
            headers=self.response_headers,
            end_stream=not self.response_body
        )
        if self.response_body:
            self.connection.send_data(
                stream_id=self.stream_id,
                data=self.response_body,
                end_stream=True
            )
        self.transmit()


class HttpQuicServerHandler(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._handlers: Dict[int, HttpRequestHandler] = {}
        self._http: Optional[HttpConnection] = None

    def http_event_received(self, event: H3Event) -> None:
        print("HttpQuicServerHandler: receiving an http event")
        print(event)
        if isinstance(event, HeadersReceived) and event.stream_id not in self._handlers:
            authority = None
            headers = []
            http_version = "0.9" if isinstance(self._http, H0Connection) else "3"
            raw_path = b""
            method = ""
            protocol = None
            for header, value in event.headers:
                if header == b":authority":
                    authority = value
                    headers.append((b"host", value))
                elif header == b":method":
                    method = value.decode()
                elif header == b":path":
                    raw_path = value
                elif header == b":protocol":
                    protocol = value.decode()
                elif header and not header.startswith(b":"):
                    headers.append((header, value))

            if b"?" in raw_path:
                path_bytes, query_string = raw_path.split(b"?", maxsplit=1)
            else:
                path_bytes, query_string = raw_path, b""
            path = path_bytes.decode()
            self._quic._logger.info("HTTP request %s %s", method, path)

            # FIXME: add a public API to retrieve peer address
            client_addr = self._http._quic._network_paths[0].addr
            client = (client_addr[0], client_addr[1])

            scope: Dict
            extensions: Dict[str, Dict] = {}
            if isinstance(self._http, H3Connection):
                extensions["http.response.push"] = {}
            scope = {
                "client": client,
                "extensions": extensions,
                "headers": headers,
                "http_version": http_version,
                "method": method,
                "path": path,
                "query_string": query_string,
                "raw_path": raw_path,
                "root_path": "",
                "scheme": "https",
                "type": "http",
            }
            handler = HttpRequestHandler(
                authority=authority,
                connection=self._http,
                protocol=self,
                scope=scope,
                stream_ended=event.stream_ended,
                stream_id=event.stream_id,
                transmit=self.transmit,
            )
            self._handlers[event.stream_id] = handler
            handler.http_event_received(event)
            self.send_response_task = asyncio.create_task(handler.send_response())
        elif (
            isinstance(event, (DataReceived, HeadersReceived))
            and event.stream_id in self._handlers
        ):
            handler = self._handlers[event.stream_id]
            handler.http_event_received(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol.startswith("h3-"):
                self._http = H3Connection(self._quic)
            elif event.alpn_protocol.startswith("hq-"):
                self._http = H0Connection(self._quic)
        elif isinstance(event, DatagramFrameReceived):
            if event.data == b"quack":
                self._quic.send_datagram_frame(b"quack-ack")

        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


def configure_http3_server(listen_port, server_port, https_pem, ca_pem, listening_sentinel):

    HttpQuicServerHandler.cert_file = https_pem
    HttpQuicServerHandler.ca_file = ca_pem

    try:
        os.mkdir('quic_log_directory')
    except FileExistsError:
        pass
    quic_logger = QuicDirectoryLogger('quic_log_directory')
    secrets_log_file = open('tls_secrets.log', "a")
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
        quic_logger=quic_logger,
        secrets_log_file=secrets_log_file,
    )

    configuration.load_cert_chain(https_pem, ca_pem)
    ticket_store = SessionTicketStore()

    # TODO
    # In 3.7: how about asyncio.run(serve(...))
    loop = asyncio.get_event_loop()
    print("Serving HTTP/3 Proxy on {}:{} with pem '{}', forwarding to {}:{}".format(
        "127.0.0.1", listen_port, https_pem, "127.0.0.1", server_port))
    loop.run_until_complete(
        serve(
            '0.0.0.0',
            listen_port,
            configuration=configuration,
            create_protocol=HttpQuicServerHandler,
            session_ticket_fetcher=ticket_store.pop,
            session_ticket_handler=ticket_store.add
        )
    )

    # Indicate to the caller that the quic socket is configured and listening.
    Path(listening_sentinel).touch()

    try:
        loop.run_forever()
    except KeyboardInterrupt as e:
        # The calling test_proxy.py will handle this.
        print("Handling KeyboardInterrupt")
        raise e
    except SystemExit:
        pass
