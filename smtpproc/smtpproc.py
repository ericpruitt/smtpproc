#!/usr/bin/env python3
import collections
import email.utils
import logging
import os
import re
import socket
import ssl
import time

__all__ = ["ACCEPTED_WITHOUT_VRFY", "BAD_SEQUENCE_OF_COMMANDS",
    "CLOSING_TRANSMISSION", "CONSOLE_LOG_HANDLER", "DEFAULT_CIPHER_LIST",
    "DOMAIN_DOES_NOT_ACCEPT_MAIL", "INSUFFICIENT_STORAGE", "LineTooLong",
    "LOCAL_ERROR", "LOGGER", "LOGGING_FORMATTER", "MAILBOX_NAME_NOT_ALLOWED",
    "MAILBOX_UNAVAILABLE", "NOT_IMPLEMENTED", "NOT_RECOGNIZED", "OKAY",
    "PARAMETER_NOT_IMPLEMENTED", "SERVICE_NOT_AVAILABLE", "SERVICE_READY",
    "SMTPCode", "SMTP_HELP", "SMTPProcessor", "START_MAIL", "STORAGE_EXCEEDED",
    "SYNTAX_ERROR", "SYSTEM_STATUS", "TEMPORARY_ERROR", "TRANSACTION_FAILED",
    "USER_NOT_LOCAL_251", "USER_NOT_LOCAL_551"]


class SMTPCode(collections.namedtuple('SMTPCode', ['code', 'description'])):
    """
    Numeric SMTP code and human-readable description.
    """


class LineTooLong(Exception):
    """
    Raised when the amount of data read is greater than the line buffer.
    """


class SMTPProcessor:
    """
    This class handles SMTP negotiations with a client then passes
    recipients and message data to a delivery handler. After instantiating
    the SMTPProcessor with a socket and delivery handler, communication is
    started with the process method:

    >>> server.listen(1)
    >>> connection, _ = server.accept()
    >>> processor = SMTPProcessor(connection, handler)
    >>> processor.process()

    From there, data will be passed to the delivery handler as needed.
    """
    hostname = socket.getfqdn(socket.gethostname())
    smtp_base_commands = {'HELO', 'EHLO', 'NOOP', 'RSET', 'QUIT'}
    smtp_functions = {'HELO', 'EHLO', 'MAIL', 'RCPT'}
    smtp_statements = {'NOOP', 'RSET', 'QUIT', 'DATA'}

    RE_MAIL_SIZE = re.compile("\s+SIZE=([0-9]+)", re.I)
    RE_MAIL_BODY = re.compile("\s+BODY=(7BIT|8BITMIME)", re.I)

    def __init__(self, socket_, delivery_handler, certfile=None, keyfile=None,
      ssl_context=None, max_line_length=8192, servername='SMTPProcessor'):
        self.ssl_enabled = False
        self.implemented_commands = self.smtp_statements | self.smtp_functions

        if not (certfile and keyfile) and (certfile or keyfile):
            raise ValueError('A certificate must accompany a key file.')

        if ssl_context:
            self.ssl_context = ssl_context
            self.ssl_enabled = True
        elif certfile and keyfile:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.ssl_context.set_ciphers('HIGH:!aNULL:!eNULL:@STRENGTH')

        if certfile and keyfile:
            self.ssl_context.load_cert_chain(certfile, keyfile)
            self.ssl_enabled = True

        if self.ssl_enabled:
            self.implemented_commands |= {'STARTTLS'}

        self.delivery_handler = delivery_handler
        self.lines = self._iterlines()
        self.max_line_length = max_line_length
        self.servername = servername
        self.socket = socket_

        self.client_host = None
        self.envelope_from = None

    def _iterlines(self):
        """
        Yield lines from instance socket.
        """
        buffered = b''
        while True:
            received = self.socket.recv(4096)
            if not received:
                if buffered:
                    # If the buffer is populated, a line was left unterminated.
                    raise socket.error("Connection closed unexpectedly.")
                yield received
                continue

            if b'\n' in received:
                if buffered:
                    received = buffered + received
                    buffered = b''

                # The splitlines method will split on lone CR's, but since I
                # only consider CRLF and LF valid line terminators, any data
                # not terminated with LF should be buffered until an LF is
                # encountered.
                for line in received.splitlines(True):
                    if line.endswith(b'\n'):
                        if (len(line) + len(buffered)) > self.max_line_length:
                            raise LineTooLong("Line size: %i" % len(line))
                        elif buffered:
                            yield buffered + line
                            buffered = b''
                        else:
                            yield line
                    else:
                        buffered += line
            else:
                buffered += received

            if len(buffered) > self.max_line_length:
                raise LineTooLong("Too much data in internal buffer.")

    def _readline(self):
        """
        Return next available line from instance socket.
        """
        return next(self.lines)

    def _write(self, data):
        """
        Send raw data to client.
        """
        self.socket.sendall(data)

    def send(self, code, message):
        """
        Send client numeric SMTP code and human-readable message. If
        `message` is an iterable, each element will be sent as a separate
        line.
        """
        if isinstance(message, str):
            message = (message,)

        try:
            for add_dash, line in enumerate(message, 1 - len(message)):
                stanza = "%i%s%s\r\n" % (code, '-' if add_dash else ' ', line)
                LOGGER.debug("Sent: %s", stanza.strip())
                self._write(stanza.encode('ascii'))

            if code == CLOSING_TRANSMISSION.code:
                self.socket.shutdown(socket.SHUT_RDWR)

        except IOError as exc:
            # If there's an error while sending the closing transmission
            # message, ignore it.
            if code != CLOSING_TRANSMISSION.code:
                raise
            else:
                self.socket.close()
                LOGGER.info("Connection closed.")

        return SMTPCode(code, message)

    def smtp_reset(self, send_status=True):
        """
        Handle SMTP RSET command. Purges recipients, message buffer and
        the return-path.
        """
        self.envelope_from = None
        self.delivery_handler.reset()
        if send_status:
            return self.send(*OKAY)

    def smtp_greeting(self):
        """
        Send SMTP server greeting to client.
        """
        self.send(SERVICE_READY.code, "%s ESMTP Service Ready" % self.hostname)

    def smtp_hello(self, parameters, ehlo=False):
        """
        Respond to client HELO / EHLO greetings, and send the ESMTP
        parameter "SIZE."
        """
        self.client_host = parameters
        LOGGER.info("Client self-identifies as %s", self.client_host)

        hello_lines = ["%s welcomes %s" % (self.hostname, self.client_host)]
        if ehlo:
            hello_lines.append('8BITMIME')
            if self.ssl_enabled:
                hello_lines.append('STARTTLS')
            if self.delivery_handler.max_size:
                hello_lines.append('SIZE %i' % self.delivery_handler.max_size)

        return self.send(OKAY.code, hello_lines)

    def smtp_starttls(self):
        """
        Negotiate TLS connection on socket.
        """
        try:
            self.send(*SERVICE_READY)
            self.socket = self.ssl_context.wrap_socket(self.socket, True)
            self.lines = self._iterlines()
            self.smtp_reset(send_status=False)
            return OKAY
        except Exception as exc:
            LOGGER.exception("Exception in smtp_starttls")
            return self.send(LOCAL_ERROR.code, str(exc))

    def smtp_mail(self, parameters):
        """
        Handle parameters for SMTP MAIL command. The instance variable
        `envelope_from` is set when this method is called and succeeds.
        """
        # Ignore message body encoding settings. More on this at
        # http://cr.yp.to/smtp/8bitmime.html.
        parameters = self.RE_MAIL_BODY.sub("", parameters)

        if not parameters.upper().startswith("FROM:"):
            return self.send(*SYNTAX_ERROR)

        match = self.RE_MAIL_SIZE.search(parameters)
        if match:
            if int(match.group(1)) > self.delivery_handler.max_size:
                return self.send(*STORAGE_EXCEEDED)
            parameters = self.RE_MAIL_SIZE.sub("", parameters)

        # Remove "FROM:" from parameters
        parameters = parameters[5:].strip()

        if not parameters:
            return self.send(*SYNTAX_ERROR)

        _, self.envelope_from = email.utils.parseaddr(parameters)
        return self.send(*OKAY)

    def smtp_recipient(self, parameters):
        """
        Attempt to add message recipients and return an appropriate SMTPCode on
        success or failure.
        """
        _, recipient = email.utils.parseaddr(parameters)
        if not recipient:
            return self.send(*SYNTAX_ERROR)
        else:
            return self.send(*self.delivery_handler.add_recipient(recipient))

    @property
    def relay_headers(self):
        """
        Return SMTP relay headers.
        """
        clientip, clientport = self.socket.getpeername()
        format_values = {
            'localhost': self.hostname,
            'clienthost': self.client_host,
            'clientip': clientip,
            'port': clientport,
            'from': self.envelope_from,
            'date': time.strftime('%a, %d %b %Y %H:%M:%S %z', time.gmtime()),
            'eol': os.linesep,
            'servername': self.servername,
        }

        header = (
            "Received: from %(clienthost)s ([%(clientip)s]:%(port)i)%(eol)s"
            "\tby %(localhost)s with %(servername)s%(eol)s"
            "\t(envelope-from <%(from)s>); %(date)s%(eol)s"
        ) % format_values

        return header.encode('ascii')

    def smtp_data(self):
        """
        Pass received message data to member delivery handler.
        """
        try:
            status = self.delivery_handler.write(self.relay_headers)
            if status.code != OKAY.code:
                return self.send(*status)
        except Exception as exc:
            return self.send(LOCAL_ERROR.code, str(exc))

        self.send(*START_MAIL)
        eol_bytes = os.linesep.encode('ascii')
        previous_eol_was_crlf = False

        while True:
            line = self._readline()
            if not line:
                raise Exception("Client disconnected.")

            if line.startswith(b'.'):
                if line == b'.\r\n' and previous_eol_was_crlf:
                    break
                line = line[1:]

            try:
                # Convert to native line endings
                if line.endswith(b'\r\n'):
                    status = self.delivery_handler.write(line[:-2] + eol_bytes)
                    previous_eol_was_crlf = True
                else:
                    status = self.delivery_handler.write(line[:-1] + eol_bytes)
                    previous_eol_was_crlf = False

                if status.code != OKAY.code:
                    return self.send(*status)

            except Exception as exc:
                return self.send(LOCAL_ERROR.code, str(exc))

        delivery_status = self.delivery_handler.deliver()
        LOGGER.info("Message delivery status: %s", delivery_status)
        self.smtp_reset(send_status=False)
        return self.send(*delivery_status)

    def dispatch(self, command, parameters, sequence):
        """
        Manage SMTP flow control and call the appropriate method to handle the
        SMTP command and the given parameters, and return an iterable
        containing the status of the last command and next set of legal
        commands.
        """
        command = command.upper()

        if command not in self.implemented_commands:
            LOGGER.warning("Unrecognized command: %s %s", command, parameters)
            status = self.send(*NOT_RECOGNIZED)

        elif command not in sequence:
            LOGGER.warning("Out of sequence command '%s'", command)
            status = self.send(*BAD_SEQUENCE_OF_COMMANDS)

        elif parameters and command in self.smtp_statements:
            status = self.send(SYNTAX_ERROR.code, "Command uses no parameters")

        elif not parameters and command in self.smtp_functions:
            status = self.send(SYNTAX_ERROR.code, "Missing parameter(s)")

        elif command == 'RSET':
            status = self.smtp_reset()
            if status.code == OKAY.code:
                return status, self.smtp_base_commands | {'MAIL'}

        elif command in ('HELO', 'EHLO'):
            ehlo = command == 'EHLO'
            status = self.smtp_hello(parameters, ehlo=ehlo)
            if status.code == OKAY.code:
                if self.ssl_enabled:
                    return status, sequence | {'STARTTLS', 'MAIL'}
                return status, sequence | {'MAIL'}

        elif command == 'STARTTLS':
            status = self.smtp_starttls()
            if status.code == OKAY.code:
                LOGGER.info("TLS handshake completed.")
                return status, self.smtp_base_commands

        elif command == 'MAIL':
            status = self.smtp_mail(parameters)
            if status.code == OKAY.code:
                return status, self.smtp_base_commands | {'RCPT'}

        elif command == 'RCPT':
            status = self.smtp_recipient(parameters)
            if status.code == OKAY.code:
                return status, sequence | {'DATA'}

        elif command == 'DATA':
            status = self.smtp_data()
            if status.code == OKAY.code:
                return status, self.smtp_base_commands

        elif command == 'QUIT':
            return None, None

        return status, sequence

    def process(self):
        """
        Begin communicating with client and processing SMTP stream.
        """
        clientip, _ = self.socket.getpeername()
        LOGGER.info("Remote host: %s", clientip)
        self.smtp_greeting()

        # This is safe because sequence is not modified
        sequence = self.smtp_base_commands
        while sequence:
            try:
                line = self._readline().decode('ascii').strip()
                if not line:
                    raise IOError("No data received from client.")

                LOGGER.debug("Received: %s", line)
                command, params = line.split(' ', 1)

            except IOError as exc:
                self.delivery_handler.reset()
                LOGGER.exception("IOError while reading data.")
                break

            except UnicodeDecodeError:
                self.send(SYNTAX_ERROR.code, "SMTP command not ASCII encoded.")
                continue

            except ValueError:
                # command, params assignment failed because the split only
                # produced a single element.
                command, params = line, None

            try:
                status, sequence = self.dispatch(command, params, sequence)
            except Exception as exc:
                LOGGER.exception("Exception while dispatching %s", command)
                break

            if status and sequence:
                LOGGER.debug("Status: %i %s", status.code, status.description)

        self.send(*CLOSING_TRANSMISSION)


#
#                      --- RFC 2821 SMTP Status Codes ---
#
SYSTEM_STATUS = SMTPCode(211, "ESMTP server online")
SMTP_HELP = SMTPCode(214, "http://www.ietf.org/rfc/rfc2821.txt")
SERVICE_READY = SMTPCode(220, "ESMTP Service Ready")
CLOSING_TRANSMISSION = SMTPCode(221, "Server closing transmission channel")
OKAY = SMTPCode(250, "Requested action completed")
USER_NOT_LOCAL_251 = SMTPCode(251, "User not local")
ACCEPTED_WITHOUT_VRFY = SMTPCode(252, "Mail accepted but cannot VRFY user")
START_MAIL = SMTPCode(354,  "Start mail input; end with <CRLF>.<CRLF>")
SERVICE_NOT_AVAILABLE = SMTPCode(421, "Service not available")
TEMPORARY_ERROR = SMTPCode(450, "Temporary problem, try again later")
LOCAL_ERROR = SMTPCode(451, "Local error in processing")
INSUFFICIENT_STORAGE = SMTPCode(452, "Insufficient system storage")
NOT_RECOGNIZED = SMTPCode(500, "Command not recognized")
SYNTAX_ERROR = SMTPCode(501, "Syntax error in command parameters")
NOT_IMPLEMENTED = SMTPCode(502, "Command not implemented")
BAD_SEQUENCE_OF_COMMANDS = SMTPCode(503, "Bad sequence of commands.")
PARAMETER_NOT_IMPLEMENTED = SMTPCode(504, "Parameter not implemented")
DOMAIN_DOES_NOT_ACCEPT_MAIL = SMTPCode(521, "Mail not accepted here")
MAILBOX_UNAVAILABLE = SMTPCode(550, "Mailbox unavailable")
USER_NOT_LOCAL_551 = SMTPCode(551, "User not local")
STORAGE_EXCEEDED = SMTPCode(552, "Message exceeds storage allocation")
MAILBOX_NAME_NOT_ALLOWED = SMTPCode(553, "Mailbox name not allowed")
TRANSACTION_FAILED = SMTPCode(554, "Transaction failed")

#
#                           --- Logging Objects ---
#
LOGGING_FORMATTER = logging.Formatter('%(asctime)s [%(process)i] %(message)s')

CONSOLE_LOG_HANDLER = logging.StreamHandler()
CONSOLE_LOG_HANDLER.setFormatter(LOGGING_FORMATTER)
CONSOLE_LOG_HANDLER.setLevel(logging.DEBUG)

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
LOGGER.addHandler(CONSOLE_LOG_HANDLER)


# Launch unit tests when module is executed alone
if __name__ == "__main__":
    import tests.test_smtpproc
    import unittest
    unittest.main(tests.test_smtpproc)
