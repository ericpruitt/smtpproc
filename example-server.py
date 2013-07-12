#!/usr/bin/env python3
import socket

import smtpproc
import smtpproc.handlers

# Create delivery handler that will pipe incoming messages into procmail.
mda = smtpproc.handlers.SubprocessDeliveryHandler(['/usr/bin/procmail'])

# Bind to port 25 and listen for connections
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 25))
server.listen(1)

# Accept connections and process incoming email forever.
while True:
    connection, _ = server.accept()
    processor = smtpproc.SMTPProcessor(connection, mda)
    processor.process()
