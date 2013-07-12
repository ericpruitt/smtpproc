#!/usr/bin/env python2.6

import collections
import email.utils
import errno
import logging
import os
import re
import select
import smtplib
import socket
import ssl
import subprocess
import time
import textwrap

HEADER_WRAPPER = textwrap.TextWrapper(
  subsequent_indent='\t', expand_tabs=False, width=72, break_long_words=False,
  break_on_hyphens=False)

ALIAS_FILES = ('/etc/aliases', '/etc/passwd')
ALIAS_FILE_MTIMES = dict(zip(ALIAS_FILES, (0,) * len(ALIAS_FILES)))
MAIL_USERS = set()

SMTPCode = collections.namedtuple('SMTPCode', ['code', 'message'])

BAD_SEQUENCE_OF_COMMANDS = SMTPCode(503, "Bad sequence of commands.")
CLOSING_TRANSMISSION = SMTPCode(221, "Server closing transmission channel.")
LOCAL_ERROR = SMTPCode(451, "Local error in processing")
MAILBOX_UNAVAILABLE = SMTPCode(550, "Mailbox unavailable")
NOT_IMPLEMENTED = SMTPCode(502, "Command not implemented.")
OKAY = SMTPCode(250, "Requested action completed.")
SERVICE_NOT_AVAILABLE = SMTPCode(421, "Service not available")
SERVICE_READY = SMTPCode(220, "%s ESMTP Service Ready" % socket.gethostname())
START_MAIL = SMTPCode(354,  "Start mail input; end with <CRLF>.<CRLF>")
STORAGE_EXCEEDED = SMTPCode(552, "Message exceeds storage allocation")
SYNTAX_ERROR = SMTPCode(501, "Syntax error in command parameters")
TRANSACTION_FAILED = SMTPCode(554, "Transaction failed")

LOGGING_FORMATTER = logging.Formatter(
    '%(created)-10i.%(process)-6d %(message)s')

CONSOLE_LOG_HANDLER = logging.StreamHandler()
CONSOLE_LOG_HANDLER.setFormatter(LOGGING_FORMATTER)
CONSOLE_LOG_HANDLER.setLevel(logging.DEBUG)

LOGGER = logging.getLogger('smtpproc')
LOGGER.setLevel(logging.INFO)
LOGGER.addHandler(CONSOLE_LOG_HANDLER)


class SSLFakeFile:
    """
    A fake file like object that wraps an SSLObject.  It only supports write,
    readline, flush and close.
    """
    def __init__(self, sslobj):
        self.sslobj = sslobj

    def write(self, data):
        self.sslobj.send(data)

    def readline(self):
        data_buffer = list()
        character = None
        while character != "\n":
            character = self.sslobj.read(1)
            if not character:
                break
            data_buffer.append(character)

        return ''.join(data_buffer)

    def fileno(self):
        return self.sslobj.fileno()

    def flush(self):
        pass

    def close(self):
        pass


class MisbehavingClientException(Exception):
    """
    Raised when client generates too many errors during SMTP exchange.
    """


class SMTPSocketProcessor(object):
    servername = 'SMTPSocketProcessor'
    commands_without_args = ('NOOP', 'RSET', 'QUIT', 'DATA', 'STARTTLS')
    commands_with_args = ('HELO', 'EHLO', 'MAIL', 'RCPT')
    implemented = commands_without_args + commands_with_args

    RE_MAIL_SIZE = re.compile("\s+SIZE=([0-9]+)", re.I)
    RE_MAIL_BODY = re.compile("\s+BODY=(7BIT|8BITMIME)", re.I)

    def __init__(self, smtpsocket, deliveryhandler, keyfile=None,
      certfile=None, max_size=20000000, pipeline_penalty=None, max_penalties=3):
        self.certfile = certfile
        self.deliveryhandler = deliveryhandler
        self.keyfile = keyfile
        self.max_penalties = max_penalties
        self.max_size = max_size
        # Use 4/3rds of the given max_size as the byte limit since some senders
        # may use pre base-64-encoded size when determining whether or not a
        # message is too large.
        self._max_size = max_size * 4 // 3
        self.pipeline_penalty = pipeline_penalty
        self.smtpsocket = smtpsocket
        self.socketfile = smtpsocket.makefile()
        self.starttls_available = self.keyfile and self.certfile

        self.client_host = None
        self.envelope_from = None
        self.mail_data_buffer = list()
        self.penalties = 0

    def send(self, code, message, ehlo_dash=False):
        """
        Send client numerical SMTP code and human-readable message.
        """
        # Check for misbehaving clients that send data before we are ready
        if self.pipeline_penalty and code not in (
          BAD_SEQUENCE_OF_COMMANDS.code, CLOSING_TRANSMISSION.code):
            data_pending, _, _ = select.select([self.socketfile], [], [], 0)
            if data_pending:
                self.penalties += self.pipeline_penalty
                self.error(BAD_SEQUENCE_OF_COMMANDS.code, "No pipelining!")

        space = '-' if ehlo_dash else ' '
        LOGGER.debug(">>> %i%s%s" % (code, space, message))
        self.socketfile.write("%i%s%s\r\n" % (code, space, message))
        self.socketfile.flush()

    def error(self, code, message):
        """
        Same as the class method `send` accept "Error: " is prepended to the
        message, and the penalty counter is incremented.
        """
        self.send(code, "Error: " + message)
        self.penalties += 1
        if self.max_penalties and self.penalties > self.max_penalties:
            self.send(CLOSING_TRANSMISSION.code, "Unacceptable behaviour.")
            self.socketfile.close()
            raise MisbehavingClientException("Too many errors during exchange")

    def run(self):
        """
        Begin communicating with client and processing SMTP stream.
        """
        self.send(*SERVICE_READY)

        base_commands = set(('HELO', 'EHLO', 'NOOP', 'RSET', 'QUIT'))
        accepted_commands = set(base_commands)
        while True:
            line = self.socketfile.readline()
            if not line:
                break

            LOGGER.debug("... %r" % line)
            line = line.strip()

            try:
                command, argument = line.split(' ', 1)

            except ValueError:
                command, argument = line, None

            command = command.upper()

            if command not in self.implemented:
                self.error(*NOT_IMPLEMENTED)

            elif command not in accepted_commands:
                self.error(*BAD_SEQUENCE_OF_COMMANDS)

            elif argument and command in self.commands_without_args:
                self.error(SYNTAX_ERROR.code, "Command accepts no arguments")

            elif not argument and command in self.commands_with_args:
                self.error(SYNTAX_ERROR.code, "Missing one or more arguments")

            elif command == 'RSET':
                if self.smtp_reset():
                    accepted_commands = set(base_commands) | set(('MAIL',))

            elif command in ('HELO', 'EHLO'):
                if self.smtp_hello(argument, ehlo=(command == 'EHLO')):
                    accepted_commands.update(('MAIL', 'STARTTLS'))

            elif command == 'STARTTLS':
                if self.starttls_available:
                    self.send(*SERVICE_READY)
                    if self.smtp_starttls():
                        accepted_commands = set(base_commands)

                else:
                    self.error(*NOT_IMPLEMENTED)

            elif command == 'MAIL':
                if self.smtp_mail(argument):
                    accepted_commands = set(base_commands) | set(('RCPT',))

            elif command == 'RCPT':
                if self.smtp_recipient(argument):
                    accepted_commands.add('DATA')

            elif command == 'DATA':
                if self.smtp_data():
                    accepted_commands = set(('QUIT',))

            elif command == 'QUIT':
                self.pipeline_penalty = None
                self.send(*CLOSING_TRANSMISSION)
                self.socketfile.close()
                break

        LOGGER.info("Connection closed.")

    def smtp_reset(self, send_status=True):
        """
        Handle SMTP RSET command. Purges recipients, message buffer and
        the return-path.
        """
        self.mail_data_buffer = list()
        self.envelope_from = None
        self.deliveryhandler.reset()
        if send_status:
            self.send(*OKAY)
        return True

    def smtp_hello(self, parameters, ehlo=False):
        """
        Respond to client HELO and EHLO greetings and send the ESMTP parameter
        SIZE.
        """
        self.client_host = parameters.strip()
        if ehlo:
            self.send(OKAY.code, SERVICE_READY.message, ehlo_dash=True)
            if self.starttls_available:
                self.send(OKAY.code, "STARTTLS", ehlo_dash=True)
            self.send(OKAY.code, 'SIZE %i' % self.max_size, ehlo_dash=True)
            self.send(OKAY.code, '8BITMIME')
        else:
            self.send(*OKAY)

        return True

    def smtp_starttls(self):
        """
        Initiate TLS on SMTP socket.
        """
        try:
            self.smtpsocket = ssl.wrap_socket(
              self.smtpsocket, self.keyfile, self.certfile, server_side=True)
            self.socketfile = SSLFakeFile(self.smtpsocket)
            self.smtp_reset(send_status=False)
            return True
        except Exception as exc:
            self.error(LOCAL_ERROR.code, str(exc))

    def smtp_mail(self, parameters):
        """
        Handle parameters for SMTP MAIL command. The instance variable
        `envelope_from` is set when this method is called and succeeds.
        """
        parameters = self.RE_MAIL_BODY.sub("", parameters)
        match = self.RE_MAIL_SIZE.search(parameters)
        if match and int(match.group(1)) > self._max_size:
            self.error(*STORAGE_EXCEEDED)
            parameters = self.RE_MAIL_SIZE.sub("", parameters).strip()

        if not parameters.upper().startswith("FROM:"):
            self.error(*SYNTAX_ERROR)

        parameters = parameters[5:].strip()
        if not parameters:
            self.error(*SYNTAX_ERROR)

        _, self.envelope_from = email.utils.parseaddr(parameters)
        LOGGER.info("Envelope from <%s>" % self.envelope_from)
        self.send(*OKAY)
        return True

    def smtp_recipient(self, parameters):
        """
        Handle parameters for SMTP RCPT command. Messages recipients are added
        to the instance variable `recipients`.
        """
        _, recipient = email.utils.parseaddr(parameters)
        if not recipient:
            self.error(*SYNTAX_ERROR)
        else:
            response = self.deliveryhandler.add_recipient(recipient)
            if response.code == OKAY.code:
                self.send(*response)
                return True
            else:
                self.error(*response)

    @property
    def relay_headers(self):
        """
        Return SMTP relay headers.
        """
        clienthost, clientport = self.smtpsocket.getpeername()
        format_values = {
            'localhost': socket.getfqdn(socket.gethostname()),
            'clienthostname': self.client_host,
            'clientip': clienthost,
            'port': clientport,
            'from': self.envelope_from,
            'date': time.strftime('%a, %d %b %Y %H:%M:%S %z', time.gmtime()),
            'eol': os.linesep,
            'servername': self.servername,
        }

        return (
          "Received: from %(clienthostname)s ([%(clientip)s]:%(port)i)%(eol)s"
          "\tby %(localhost)s with %(servername)s%(eol)s"
          "\t(envelope-from <%(from)s>); %(date)s%(eol)s"
        ) % format_values

    def smtp_data(self):
        """
        Handle SMTP DATA command. Message lines are buffered in memory then
        written out to maildatastream with relay headers once the client has
        finished sending data.
        """
        bytes_read = 0
        self.send(*START_MAIL)
        self.deliveryhandler.write(self.relay_headers)

        while True:
            line = self.socketfile.readline()
            if not line:
                raise Exception("Client disconnected.")

            LOGGER.debug("... %r" % line)
            bytes_read += len(line)
            if self.max_size and bytes_read > self._max_size:
                self.error(*STORAGE_EXCEEDED)
                return

            if bytes_read and line.startswith('.'):
                if line == '.\r\n':
                    break
                line = line[1:]

            # Convert to native line endings
            if line.endswith('\r\n'):
                self.deliveryhandler.write(line[:-2] + os.linesep)
            else:
                self.deliveryhandler.write(line[:-1] + os.linesep)

        try:
            self.deliveryhandler.deliver()
            self.send(OKAY.code, "Accepted %i bytes" % bytes_read)
            return True
        except Exception as exc:
            self.error(LOCAL_ERROR.code, str(exc))
        finally:
            self.smtp_reset(send_status=False)


class MessageDeliveryHandler(object):
    def __init__(self, recipients=None):
        self.recipients = recipients or set()

    def add_recipient(self, recipient):
        """
        Add message recipient then return an SMTP status code and message.
        """
        self.recipients.add(recipient)
        if address_accepted_locally(recipient):
            return SMTPCode(OKAY.code, "Accepted recipient <%s>" % recipient)
        else:
            return MAILBOX_UNAVAILABLE

    def write(self, data):
        """
        Add data to message file / buffer.
        """

    def reset(self):
        """
        Called whenever an RSET command is received and after message delivery.
        """

    def deliver(self):
        """
        Deliver message to recipients.
        """


class PipedMessageDeliveryHandler(MessageDeliveryHandler):
    processed = 0

    def __init__(self, directory, command):
        format_values = {
            'count': self.__class__.processed,
            'time': time.time(),
            'pid': os.getpid(),
            'hostname': socket.gethostname(),
        }

        self.directory = directory
        self.mid = '%(time)i.%(pid)i_%(count)i.%(hostname)s' % format_values
        self.message_path = path = os.path.join(directory, self.mid)
        self.command = command
        self._command = [arg if arg is not None else path for arg in command]
        self.commandproc = None
        super(self.__class__, self).__init__()

    def write(self, data):
        if not self.commandproc:
            self.commandproc = subprocess.Popen(
              self._command, stdin=subprocess.PIPE)

            if len(self.recipients) == 1:
                recipient = tuple(self.recipients)[0]
                lines = HEADER_WRAPPER.wrap('X-Envelope-To: %s' % recipient)
            else:
                recipients = ', '.join(self.recipients)
                lines = HEADER_WRAPPER.wrap('X-Recipients: %s' % recipients)

            self.commandproc.stdin.write('\n'.join(lines) + '\n')

        self.commandproc.stdin.write(data)
        self.commandproc.stdin.flush()

    def reset(self):
        if self.commandproc:
            try:
                self.commandproc.kill()
            except Exception:
                pass
            finally:
                if os.path.exists(self.message_path):
                    os.remove(self.message_path)

        self.__init__(directory=self.directory, command=self.command)

    def deliver(self):
        if self.commandproc:
            LOGGER.info("Delivered message %s." % self.mid)
            self.commandproc.stdin.close()
            try:
                self.commandproc.wait()
            except OSError as exc:
                if exc.errno != errno.ECHILD:
                    raise exc

            # Set commandproc to None so the message file will not be removed
            # when reset is called.
            self.commandproc = None

        self.__class__.processed += 1


def mailbox_available(user):
    """
    Return boolean indicating whether or not a mailbox for the user exists
    locally.
    """
    for path in ALIAS_FILES:
        mtime = os.stat(path).st_mtime
        if mtime != ALIAS_FILE_MTIMES[path]:
            try:
                with open(path) as aliases:
                    for line in aliases:
                        line = line.strip()
                        if line.startswith('#'):
                            continue

                        try:
                            name, _ = line.split(':', 1)
                            MAIL_USERS.add(name.lower())
                        except Exception:
                            pass

            except Exception:
                pass

            finally:
                ALIAS_FILE_MTIMES[path] = mtime

    return user.lower() in MAIL_USERS


def address_accepted_locally(recipient):
    """
    Return boolean indicating whether or not mail is accepted for a recipient.
    """
    user, domain = recipient.split('@')
    return (domain in socket.getfqdn(socket.gethostname()) and
      user_found_here(user))
