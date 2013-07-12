smtpproc
========

Synposis
--------

The SMTPProcessor is not a stand-alone SMTP server but acts as a communication
negotiator and data relay for incoming emails that can be used to create a
server. Message delivery is handled by a delivery handler that implements
several functions and properties that the SMTPProcessor instance will call.
Using the provided SubprocessDeliveryHandler in conjunction with the
SMTPProcessor class, we can create a simple server that uses procmail to
deliver emails with less than a dozen lines:

    >>> import socket
    >>> from smtpproc.handlers import SubprocessDeliveryHandler
    >>> from smtpproc import SMTPProcessor
    >>> mda = SubprocessDeliveryHandler(['/usr/bin/procmail'])
    >>> server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    >>> server.bind(('0.0.0.0', 25))
    >>> server.listen(1)
    >>> while True:
    ...     connection, _ = server.accept()
    ...     processor = SMTPProcessor(connection, mda)
    ...     processor.process()

This library makes use of SSL contexts and only supports Python 3.2 and up.

Delivery Handler
----------------

A delivery handler that must implement the following methods and provide a
`max_size` property:

### add_recipient(recipient) ###

Add the given recipient to the message. Must return an `SMTPCode` indicating
whether or not the recipient was accepted for delivery.

### write(data) ###

Add the given bytes to the message data buffer. Must return an `SMTPCode` at
the end of each write operation. If the write was successful, an `SMTPCode`
with a `code` of 250 must be returned. If `code` is 250, the code and
description will not be transmitted to the client, but any other codes will
cause the `SMTPProcess` to stop accepting mail data and send the error to the
client. In the event of an error, it is assumed that the delivery handler has
purged its internal message buffer.

### reset() ###

Purge the existing recipient list and all stored message data. No return value
expected, and if there is a problem, an exception should be raised. It is
possible for reset to be called before any data or recipients are passed to the
handler, immediately after a delivery or immediately after another reset, so it
is recommended that delivery handler implementations defer allocating resources
until `add_recipient` or `write` called.

### deliver() ###

Deliver the message data to recipients. The SMTPProcess does not explicitly
call `reset` after a delivery, so the delivery handler is responsible for
purging its internal state.

### max_size ###

Amount of data the delivery handler will accept before returning SMTP code 552
(storage exceeded). It is up to the delivery handler to enforce this limit on
data supplied to the `write` method. For unlimited message size, this should be
set to None or 0.

History
-------

### Why write your own SMTP server? ###

I wanted to host a mail server on my VPS that would encrypt all incoming
messages with a given public key before writing them to the disk. I began
looking through the documentation for postfix to see if I could implement a
pre-queue filter, but I did not see an easy way to ensure that the incoming
message data would never be written to a disk and decided it might be quicker
just to write my own SMTP server, and in the likely event that I spent more
time writing my own SMTP server than I would have writing a filter for postfix,
I would at least learn a lot about SMTP in the process.

### Creation ####

The first implementation of the SMTPProcessor was written for Python 2.6. When
I created the current implementation of the SMTPProcessor I decided to target
Python 3.2 since I hadn't done much with Python 3. In the beginning, I wrote
unit tests for the new codebase's behaviour, copied the code over from the old
SMTPProcessor and reworked it for Python 3 and the change in behaviours. After
I got the core functionality working, I switched to writing the unit tests
after implementing features.

Unit Tests
----------

The unit tests in their current state are admittedly a huge mess, but they get
the job done and have been very useful in making sure I my code works as
expected when refactoring different aspects of the server.

RFC Compliance
--------------

Although mostly RFC compliant, there are several things the processor takes
some liberties with:

- Stray carriage returns in message bodies are allowed.
- All data, whether 7-bit ASCII or octets with the first bit set, is
  transmitted as-is without conversion to quoted printable.
- Email addresses parsed from MAIL and RCPT parameters are parsed very
  liberally, and angle-brackets are optional.
- Lines may end in `\n`, but `\r\n.\r\n` must still be used to terminate the
  DATA command.
- Client hostnames are not checked for validity, but I intend to change this.
