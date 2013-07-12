#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# XXX: These unit tests are a huge mess, but they get the job done.
import sys
import os

TEST_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(TEST_DIRECTORY, os.pardir))

import random
import smtpproc
import socket
import threading
import unittest
import queue
import ssl
import smtplib


def background(function):
    """
    Function decorator used to run a function in a background thread.
    """
    def background_caller(*args, **kwargs):
        thread = threading.Thread(target=function, args=args, kwargs=kwargs)
        thread.daemon = True
        thread.start()
        return thread
    return background_caller


class FuzzySocket:
    def __init__(self, *args, **kwargs):
        fuzz_lines = list()
        for _ in range(128):
            fuzz_lines.append((
                os.urandom(random.randrange(0, 2048))).replace(b'\n', b'') + b'\r\n')
        fuzz_data = os.urandom(1024**2 * 2)
        for line in fuzz_data.split(b'\n'):
            fuzz_lines.append(line + b'\n')

        fuzz_data = b''.join(fuzz_lines)
        self.fuzz_lines = fuzz_lines
        self.fuzz_data = fuzz_data

    def recv(self, buffersize):
        read_size = random.randint(1, buffersize)
        returned, self.fuzz_data = self.fuzz_data[:buffersize], self.fuzz_data[buffersize:]
        return returned


class DeliveryHandler:
    max_size = 10000000

    def __init__(self):
        self.recipients = set()
        self.message_data = list()

    def reset(self):
        self.__init__()

    def add_recipient(self, recipient):
        self.recipients.add(recipient)
        return smtpproc.OKAY

    def write(self, data):
        self.message_data.append(data)
        return smtpproc.OKAY

    def deliver(self):
        return smtpproc.OKAY


class SharedTestFixtures(unittest.TestCase):
    simple_test_lines = (b"ZZZ\n", b"XXX\r\n", b"\n", b"QQQ\r\n", b".\r\n")
    dummy_handler = DeliveryHandler()

    @property
    def client_conn(self):
        if not hasattr(self, "_client_conn"):
            client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_conn.connect(('localhost', self.server_port))
            self._client_conn = client_conn
        return self._client_conn

    @background
    def send_lines(self, lines):
        self.client_conn.send(b''.join(lines))

    @property
    def server_connection(self):
        if not hasattr(self, "_server_connection"):
            self._server_connection, _ = self.server_socket.accept()
        return self._server_connection

    def setUp(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', 0))
        server_socket.listen(1)

        _, self.server_port = server_socket.getsockname()
        self.server_socket = server_socket

    def tearDown(self):
        if hasattr(self, "_client_conn"):
            self._client_conn.close()
            self._client_conn = None

        if hasattr(self, "_server_connection"):
            self._server_connection.close()

        self.server_socket.close()
        self.dummy_handler.reset()


class AcceptanceTests(SharedTestFixtures):
    def test_readline(self):
        self.send_lines(self.simple_test_lines)
        processor = smtpproc.SMTPProcessor(socket_=self.server_connection,
                                           delivery_handler=self.dummy_handler)

        for line in self.simple_test_lines:
            received = processor._readline()
            assert received == line

    def test_write(self):
        @background
        def serve_lines():
            processor = smtpproc.SMTPProcessor(
                socket_=self.server_connection,
                delivery_handler=self.dummy_handler)
            for line in self.simple_test_lines:
                processor._write(line)

        serve_lines()
        client_processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn, delivery_handler=self.dummy_handler)

        for line in self.simple_test_lines:
            assert client_processor._readline() == line

    def test_send(self):
        @background
        def server_send():
            processor = smtpproc.SMTPProcessor(
                socket_=self.server_connection,
                delivery_handler=self.dummy_handler)
            processor.send(200, "TEST")
            processor.send(200, ["TEST", "TEST2"])

        expected = ("200 TEST\r\n", "200-TEST\r\n", "200 TEST2\r\n")

        server_send()
        client_processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn, delivery_handler=self.dummy_handler)

        for line in expected:
            got = client_processor._readline()
            expected = bytes(line, 'ascii') if isinstance(line, str) else line
            assert got == expected

    def test_smtp_reset(self):
        exceptions = queue.Queue()

        @background
        def client():
            client_processor = smtpproc.SMTPProcessor(
                socket_=self.client_conn,
                delivery_handler=self.dummy_handler)

            try:
                assert client_processor._readline().startswith(b"250 ")
                exceptions.put(None)
                exceptions.put(None)
            except Exception as exc:
                exceptions.put(exc)

        client()
        processor = smtpproc.SMTPProcessor(socket_=self.server_connection,
                                           delivery_handler=self.dummy_handler)
        processor.envelope_from = 'BLAH'
        processor.smtp_reset()
        assert not processor.envelope_from
        assert not exceptions.get()

        processor.envelope_from = 'BLAH'
        processor.smtp_reset(send_status=False)
        assert not processor.envelope_from
        assert not exceptions.get()

    def test_ssl_setup(self):
        certfile = os.path.join(TEST_DIRECTORY, 'resources', 'test.crt')
        keyfile = os.path.join(TEST_DIRECTORY, 'resources', 'test.key')
        processor = smtpproc.SMTPProcessor(socket_=None,
                                           delivery_handler=self.dummy_handler,
                                           certfile=certfile,
                                           keyfile=keyfile)
        assert processor.ssl_enabled

    def test_smtp_ehlo_withssl(self):
        certfile = os.path.join(TEST_DIRECTORY, 'resources', 'test.crt')
        keyfile = os.path.join(TEST_DIRECTORY, 'resources', 'test.key')

        @background
        def server_actions():
            processor = smtpproc.SMTPProcessor(
                socket_=self.server_connection,
                delivery_handler=self.dummy_handler, certfile=certfile,
                keyfile=keyfile)
            processor.smtp_greeting()
            processor.smtp_hello('nobody', ehlo=True)
        server_actions()

        smtpcon = smtplib.SMTP('localhost', self.server_port)
        smtpcon.ehlo()
        assert smtpcon.has_extn('SIZE')
        assert smtpcon.has_extn('8BITMIME')
        assert smtpcon.has_extn('STARTTLS')

    def test_smtp_ehlo_nossl(self):
        @background
        def server_actions():
            processor = smtpproc.SMTPProcessor(
                socket_=self.server_connection,
                delivery_handler=self.dummy_handler)
            processor.smtp_greeting()
            processor._readline()
            processor.smtp_hello('nobody', ehlo=True)
        server_actions()
        smtpcon = smtplib.SMTP('localhost', self.server_port)
        smtpcon.ehlo()
        assert smtpcon.has_extn('SIZE')
        assert smtpcon.has_extn('8BITMIME')
        assert not smtpcon.has_extn('STARTTLS')

    def test_smtp_helo(self):
        @background
        def server_actions():
            processor = smtpproc.SMTPProcessor(
                socket_=self.server_connection,
                delivery_handler=self.dummy_handler)
            processor.smtp_greeting()
            processor._readline()
            processor.smtp_hello('nobody')
        server_actions()

        smtpcon = smtplib.SMTP('localhost', self.server_port)
        smtpcon.helo()

    def test_smtp_starttls(self):
        certfile = os.path.join(TEST_DIRECTORY, 'resources', 'test.crt')
        keyfile = os.path.join(TEST_DIRECTORY, 'resources', 'test.key')

        @background
        def server_actions():
            processor = smtpproc.SMTPProcessor(
                socket_=self.server_connection,
                delivery_handler=self.dummy_handler, certfile=certfile,
                keyfile=keyfile)
            processor.smtp_greeting()
            processor._readline()
            processor.smtp_hello('nobody', ehlo=True)
            processor._readline()
            processor.smtp_starttls()
        server_actions()

        smtpcon = smtplib.SMTP('localhost', self.server_port)
        smtpcon.starttls()

    def test_smtp_recipient(self):
        processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn,
            delivery_handler=self.dummy_handler)
        processor.smtp_recipient("bytes@example.com")
        processor.smtp_recipient("str@example.com")
        assert (set(("bytes@example.com", "str@example.com")) ==
                self.dummy_handler.recipients)

    def test_mail_valid_address(self):
        processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn,
            delivery_handler=self.dummy_handler)
        parameters = "FROM: <someone@example.com> SIZE=0"
        processor.smtp_mail(parameters)
        assert processor.envelope_from == "someone@example.com"

    def test_relay_headers(self):
        processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn,
            delivery_handler=self.dummy_handler)
        return processor.relay_headers

    def test_smtp_data(self):
        self.send_lines(self.simple_test_lines)
        processor = smtpproc.SMTPProcessor(
            socket_=self.server_connection,
            delivery_handler=self.dummy_handler)

        processor.smtp_data()
        for want, got in zip(
                self.simple_test_lines, self.dummy_handler.message_data[1:]):
            want = (want.replace(b"\r", b"").replace(
                b"\n", os.linesep.encode('ascii')))
            assert want == got

    def test_iterlines(self):
        fuzzy_socket = FuzzySocket()
        process = smtpproc.SMTPProcessor(socket_=fuzzy_socket,
            delivery_handler=None)
        for line in fuzzy_socket.fuzz_lines:
            got = process._readline()
            assert got == line

class FailureModeTests(SharedTestFixtures):
    def test_reject_big_line(self):
        maxlinelen = 1000
        lines = [b"x\n"] * 1024
        lines.append(b"xx" * 100000 + b'\n')

        self.send_lines(lines=lines)
        processor = smtpproc.SMTPProcessor(socket_=self.server_connection,
                                           max_line_length=maxlinelen,
                                           delivery_handler=self.dummy_handler)

        for line in lines:
            if len(line) > maxlinelen:
                self.assertRaises(
                    smtpproc.LineTooLong, processor._readline)
            else:
                processor._readline()

    def test_invalid_ssl_certificate(self):
        certfile = os.path.join(TEST_DIRECTORY, 'resources', 'empty.crt')
        keyfile = os.path.join(TEST_DIRECTORY, 'resources', 'empty.key')
        kwargs = dict(
            socket_=None, delivery_handler=self.dummy_handler,
            certfile=certfile, keyfile=keyfile)

        self.assertRaises(ssl.SSLError, smtpproc.SMTPProcessor, **kwargs)

    def test_ssl_certificate_missing_key_or_certfile(self):
        certfile = os.path.join(TEST_DIRECTORY, 'resources', 'empty.crt')
        keyfile = os.path.join(TEST_DIRECTORY, 'resources', 'empty.key')

        kwargs = dict(
            socket_=None, delivery_handler=self.dummy_handler,
            certfile=None, keyfile=keyfile)
        self.assertRaises(ValueError, smtpproc.SMTPProcessor, **kwargs)

        kwargs = dict(
            socket_=None, delivery_handler=self.dummy_handler,
            certfile=certfile, keyfile=None)
        self.assertRaises(ValueError, smtpproc.SMTPProcessor, **kwargs)

    def test_mail_size_exceeded(self):
        processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn,
            delivery_handler=self.dummy_handler)
        failure_size = processor.delivery_handler.max_size + 1
        parameters = "FROM: <> SIZE=%i" % failure_size
        assert (processor.smtp_mail(parameters).code ==
                smtpproc.STORAGE_EXCEEDED.code)

    def test_mail_invalid_from(self):
        processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn,
            delivery_handler=self.dummy_handler)
        parameters = "ASDAS ASD ASD ASD"
        assert (processor.smtp_mail(parameters).code ==
                smtpproc.SYNTAX_ERROR.code)

    def test_mail_no_address(self):
        processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn,
            delivery_handler=self.dummy_handler)
        parameters = "FROM: SIZE=0"
        assert (processor.smtp_mail(parameters).code ==
                smtpproc.SYNTAX_ERROR.code)

    def test_missing_status_assignment_regression(self):
        lines = ['fake','fake', 'data', 'data']
        processor = smtpproc.SMTPProcessor(
            socket_=self.client_conn,
            delivery_handler=self.dummy_handler)
        for line in lines:
            processor.dispatch(line, '', {})


class FunctionalTests(SharedTestFixtures):
    def test_deliver_without_ssl(self):
        class DummyHandler(DeliveryHandler):
            def reset(self):
                pass

        handler = DummyHandler()

        @background
        def server_actions():
            processor = smtpproc.SMTPProcessor(socket_=self.server_connection,
                                               delivery_handler=handler)
            processor.process()

        server_actions()
        smtpcon = smtplib.SMTP('localhost', self.server_port)
        message = "Qing Jao"
        sender = "client@localhost"
        receiver = "server@localhost"
        smtpcon.sendmail(sender, receiver, message)
        #TODO: Figure out why there's an unclosed resource warning
        assert sender.encode('utf8') in handler.message_data[0]
        assert handler.message_data[-1].startswith(
            message.encode('utf8'))
        smtpcon.quit()

    def test_deliver_with_ssl(self):
        class DummyHandler(DeliveryHandler):
            def reset(self):
                pass

        certfile = os.path.join(TEST_DIRECTORY, 'resources', 'test.crt')
        keyfile = os.path.join(TEST_DIRECTORY, 'resources', 'test.key')
        handler = DummyHandler()

        @background
        def server_actions():
            processor = smtpproc.SMTPProcessor(socket_=self.server_connection,
                                               delivery_handler=handler,
                                               certfile=certfile,
                                               keyfile=keyfile)
            processor.process()

        server_actions()
        smtpcon = smtplib.SMTP('localhost', self.server_port)
        smtpcon.starttls()
        message = "Qing Jao"
        sender = "client@localhost"
        receiver = "server@localhost"
        smtpcon.sendmail(sender, receiver, message)
        #TODO: Figure out why there's an unclosed resource warning
        assert sender.encode('utf8') in handler.message_data[0]
        assert handler.message_data[-1].startswith(
            message.encode('utf8'))
        smtpcon.quit()


def suite():
    acceptance_tests = unittest.makeSuite(AcceptanceTests)
    failure_mode_tests = unittest.makeSuite(FailureModeTests)
    functional_tests = unittest.makeSuite(FunctionalTests)
    return unittest.TestSuite([acceptance_tests, failure_mode_tests,
                              functional_tests])


if __name__ == "__main__":
    unittest.main()
