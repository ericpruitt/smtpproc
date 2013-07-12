#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import errno
import os
import smtpproc
import socket
import subprocess
import textwrap
import time

HEADER_WRAPPER = textwrap.TextWrapper(
    subsequent_indent='\t', expand_tabs=False, width=72,
    break_long_words=False, break_on_hyphens=False)

OUTFILE = None

class SubprocessDeliveryHandler:
    """
    This SMTPProcessor delivery handler pipes incoming messages into stdin
    of a subprocess. It accepts a list of arguments for process execution
    and directory name used as the prefix for the `OUTFILE` variable
    described further into this documentation. In the following example,
    all incoming mail processed with this delivery handler will be piped
    to procmail for processing:

    >>> from smtpproc.handlers import SubprocessDeliveryHandler
    >>> mda = SubprocessDeliveryHandler(['/usr/bin/procmail'])

    The subprocess is responsible for saving the processed email, and
    stdout and stderr are ignored by the delivery handler. However, the
    delivery handler can also generate a destination filename for
    subprocesses that accept an output file as an argument by using the
    `OUTFILE` module variable:

    >>> from smtpproc.handlers import OUTFILE, SubprocessDeliveryHandler
    >>> command = ['gpg', '-r', '6E5EFE54', '-e', '-o', OUTFILE]
    >>> gpghandler = SubprocessDeliveryHandler(command, directory='gpgmail')

    When the subprocess is started, `OUTFILE` will be substituted with a
    unique file named derived from the current time, process ID, message
    delivery count and system hostname.
    """
    processed = 0       # Number of messages processed
    max_size = 33554432 # 24MB of base64 encoded data

    def __init__(self, command, directory='.'):
        self.command = self._command = command
        self.directory = directory

        format_values = {
            'count': self.__class__.processed,
            'time': time.time(),
            'pid': os.getpid(),
            'hostname': socket.gethostname(),
        }

        self.mid = '%(time)i.%(pid)i_%(count)i.%(hostname)s' % format_values

        if OUTFILE in command:
            self.message_path = path = os.path.join(directory, self.mid)
            self._command = [v if v is not OUTFILE else path for v in command]

        self.commandproc = None
        self.recipients = set()

    def add_recipient(self, recipient):
        """
        Add message recipient then return an SMTP status code and message.
        """
        self.recipients.add(recipient)
        statusmsg = "Accepted recipient <%s>" % recipient
        return smtpproc.SMTPCode(smtpproc.OKAY.code, statusmsg)

    def write(self, data):
        """
        Write data to subprocess stdin.
        """
        if not self.commandproc:
            self.commandproc = subprocess.Popen(
              self._command, stdin=subprocess.PIPE)

            if len(self.recipients) == 1:
                recipient = tuple(self.recipients)[0]
                lines = HEADER_WRAPPER.wrap('X-Envelope-To: %s' % recipient)
            else:
                recipients = ', '.join(self.recipients)
                lines = HEADER_WRAPPER.wrap('X-Recipients: %s' % recipients)

            header_bytes = ('\n'.join(lines) + '\n').encode('utf8')
            self.commandproc.stdin.write(header_bytes)

        self.commandproc.stdin.write(data)
        self.commandproc.stdin.flush()
        return smtpproc.OKAY

    def reset(self):
        """
        Terminate existing subprocess and remove the output file if it exists.
        """
        if self.commandproc:
            try:
                self.commandproc.kill()
            except Exception:
                pass
            finally:
                try:
                    os.remove(self.message_path)
                except EnvironmentError as exc:
                    if exc.errno != errno.ENOENT:
                        raise

        self.__init__(command=self.command, directory=self.directory)

    def deliver(self):
        """
        Close pipe and wait on the subprocess to terminate.
        """
        if self.commandproc:
            self.commandproc.stdin.close()
            try:
                self.commandproc.wait()
            except EnvironmentError as exc:
                if exc.errno != errno.ECHILD:
                    raise

            # Set commandproc to None so the message file will not be removed
            # when reset is called.
            self.commandproc = None

        self.__class__.processed += 1
        statusmsg = "Message delivered. ID: %s" % self.mid
        return smtpproc.SMTPCode(smtpproc.OKAY.code, statusmsg)
