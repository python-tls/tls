.. list-table:: A TLS full handshake
   :widths: 10 30 30
   :header-rows: 1

   * - No.
     - Client
     - Server
   * - 1
     - .. compound:: Send:
         - ClientHello
     - <wait for ClientHello>
   * - 2
     - <wait for ServerHelloDone>
     - .. compound:: Send:

         - ServerHello

         - Certificate*

         - ServerKeyExchange*

         - CertificateRequest*

         - ServerHelloDone

   * - 3
     - .. compound:: Send:

         - Certificate*

         - ClientKeyExchange

         - CertificateVerify*

         - [ChangeCipherSpec]

         - Finished

     - <wait for client’s Finished>
   * - 4
     - <wait for server’s Finished>
     - .. compound:: Send:

         - [ChangeCipherSpec]

         - Finished

Hello Messages
==============

- ClientHello and ServerHello establish:

  - Protocol version

  - Session ID

  - Cipher suite

  - Compression method

- And generate:

  - ClientHello.random

  - ServerHello.random

- When the client sends a ClientHello to server, it can either respond with a
  ServerHello, or ignore it, leading to a fatal error and the closing of the
  connection.

2.Server:
=========

- Certificate:

  - If it is to be authenticated

- ServerKeyExchange:

  - If server doesn't have a certificate, or

  - if server’s certificate is for signing only

- CertificateRequest:

  - If:

    - server is authenticated, and

    - it is appropriate to the cipher suite selected

- ServerHelloDone:

  - To indicate that the hello-message phase of the handshake is complete

3.Client:
=========

- Certificate:

  - If the server sent a CertificateRequest

- ClientKeyExchange:

  - The content of this message depends on the public key algorithm selected
    between ClientHello and ServerHello

- CertificateVerify:

  - If the client certificate sent is with signing ability

- Digitally signed

  - Verifies the possession of private key in certificate

- ChangeCipherSpec:

  - Send this and copy the pending cipher spec into the current cipher spec

- Finished

  - Sent under the new algorithms, keys, and secrets

4.Server:
=========

- ChangeCipherSpec:

  - Send this and copy the pending cipher spec into the current cipher spec

- Finished

  - Sent under the new cipher spec


Session Resumption:
===================


.. list-table::
   :widths: 10 30 30
   :header-rows: 1

   * - No.
     - Client
     - Server
   * - 1
     - .. compound:: Send:

         - ClientHello

     - <wait for ClientHello>
   * - 2
     - <wait for Server's Finished>
     - .. compound:: Check session cache for a match.

       - If the session ID is not found:

         - Generate a new session ID and perform a full handshake

       - If the session ID is found:

         - Is willing to re-establish the connection under the specified
           session state:

           - If No:

             - Generate a new session ID and perform a full handshake


           - If Yes, proceed to 3.

   * - 3
     - <wait for server’s Finished>
     - .. compound:: Send:

         - ServerHello

         - [ChangeCipherSpec]

         - Finished

   * - 4
     - .. compound:: Send:

         - [ChangeCipherSpec]

         - Finished

     - <wait for client’s Finished>

1.Client:
=========

- ClientHello:

  - Sent using the session ID of the session to be resumed.

3.Server:
=========

- ServerHello:

  - Sent with the same Session ID value (as in the ClientHello message).


Server as a state machine:
==========================

.. list-table::
   :widths: 20 20 20 35
   :header-rows: 1

   * - Input
     - Current State
     - Next State
     - Output
   * - ClientHello
     - IDLE
     - CHECK_SESSION_CACHE
     - --
   * - ``id_found_somehow``
     - CHECK_SESSION_CACHE
     - WAIT_RESUME
     - .. compound:: (ServerHello,
         [ChangeCipherSpec],
         Finished)
   * - ``id_not_found_somehow``
     - CHECK_SESSION_CACHE
     - WAIT
     - .. compound:: (ServerHello,
         Certificate*,
         ServerKeyExchange*,
         CertificateRequest*,
         ServerHelloDone)
   * - Finished (from Client)
     - WAIT
     - APP_DATA
     - .. compound:: ([ChangeCipherSpec],
         Finished)
   * - Finished (from Client)
     - WAIT_RESUME
     - APP_DATA
     - --
   * - ClientHello
     - APP_DATA
     - APP_DATA
     - Alert(no_renegotiation)

Client as a state machine:
==========================

.. list-table::
   :widths: 20 20 20 35
   :header-rows: 1

   * - Input
     - Current State
     - Next State
     - Output
   * - --
     - IDLE
     - WAIT_1
     - ClientHello
   * - ServerHelloDone
     - WAIT_1
     - WAIT_2
     - .. compound:: (Certificate*,
         ClientKeyExchange,
         CertificateVerify*,
         [ChangeCipherSpec],
         Finished)
   * - Finished (from Server)
     - WAIT_1
     - APP_DATA
     - .. compound:: ([ChangeCipherSpec],
         Finished)
   * - Finished (from Server)
     - WAIT_2
     - APP_DATA
     - --
   * - HelloRequest
     - APP_DATA
     - APP_DATA
     - Alert(no_renegotiation)

----

   `*` Indicates optional or situation-dependent messages that are not always
   sent.

   Note: To help avoid pipeline stalls, ChangeCipherSpec is an
   independent TLS protocol content type, and is not actually a TLS
   handshake message.

Common states for both state machines:
======================================

.. list-table::
   :widths: 20 20 20 35
   :header-rows: 1

   * - Input
     - Current State
     - Next State
     - Output
   * - Alert(close_notify)
     - APP_DATA
     - SHUTDOWN
     - (Alert(close_notify),
       ``close_callback(False)``,
       ``indicate_EOF_to_the_application_somehow``)
   * - ``Session.alert(close_notify)``
     - APP_DATA
     - HOST_INITIATED_CLOSING
     - Alert(close_notify)
   * - Alert(close_notify)
     - HOST_INITIATED_CLOSING
     - SHUTDOWN
     - (``close_callback(True)``,
       ``indicate_EOF_to_the_application_somehow``)
   * - ``Session.write_data``
     - APP_DATA
     - APP_DATA
     - ``write_callback()``
