Python TLS API
==============

.. class:: ClientTLS(server_hostname, trust_root=DEFAULT, client_certificate_store=None)

    :param bytes server_hostname:
        The hostname of the server that will be connected to.
    :param TrustStore trust_root:
        The trust root.
    :param ClientCertificateStore client_certificate_store:
        The certificate that the client will present to the server.

    .. method:: start(write_to_wire_callback, wire_close_callback, verify_callback=None)

        :param callable write_to_wire_callback:
            Callable of one argument of ``bytes`` type.
            It will be called when TLS data should be sent over the transport.
        :param callable wire_close_callback:
            Callable of one argument of ``bool`` type, called ``immediate``.
            It will be called when the TLS protocols mandates a transport shutdown.
            The read side of the connection must always be shut down immediately and no further data should be delivered to the connection.
            If ``immediate`` is True, then the transport should close the write side of the transport and free all associated resources as soon as possible.
            If ``immediate`` is False, then the transport should make a reasonable attempt to deliver the bytes already sent to ``write_to_wire_callback`` (which will be a ``close_alert`` message), meaning it can wait for a configured timeout before closing down the write side of the connection.
        :param callable verify_callback:
            Callable of two arguments: a list of :class:`Certificate` objects, and a :class:`Connection` object.
            It will be called once per negotiation with a list of Certificates and the connection object.
            The certificates are in chain order, starting with the leaf certificate and ending with the root-most certificate.
            Specifying a verify_callback does *not* override the basic verification that PyTLS does, such as certificate chain validation, basic certificate checks, and hostname validation.
            verify_callback has no particular contract; return values will be ignored.
            If any exception is raised, the connection will be invalidated and any future calls to :py:meth:`Connection.data_from_wire` or :py:meth:`Connection.data_from_application` will raise :class:`InvalidatedError`.
            It's up to the user to decide what to do during verification, such as invoking :py:meth:`Connection.send_alert` or simply closing the connection.

        :return Connection:
            the client connection.

        Start a TLS connection.
        The write_to_wire_callback will be invoked with the initial data for TLS negotiation.


.. class:: ServerTLS(certificates, dh_params=None)

    :param ServerCertificates certificates:
        A collection of server certificates, usually an instance of either :class:`ServerCertificateChain` or :class:`SNIServerCertificates`.
    :param bytes dh_params:
        Optional diffie-hellman parameters in DER format.

    .. method:: start(write_to_wire_callback, verify_callback=None)

        :return Connection:
            the server connection.

        See ClientTLS.start.


.. class:: Connection

    .. method:: data_from_wire(input)

        :param bytes input:
            Data that was received from some low-level transport and should be processed by the TLS implementation.
        :return bytes:
            Any application data that was in the input.

        :raises TLSAlertError:
            When certain TLS Alert messages occur in the input.
        :raises BadTLSDataError:
            When the input data was somehow invalid, such as when decryption failed or the protocol was not followed.
        :raises InvalidatedError:
            When the connection has been invalidated due to a previous error and will accept no further data.

        Given data read from a transport, invoke any callbacks for e.g. connection negotiation or heartbeats, etc, and return decrypted application data, if any.
        If the input data is somehow invalid, a TLS Alert message will be passed to the write callback, and a BadTLSDataError will be raised.
        In certain cases of receipt of invalid data, after (sometimes) sending a TLS Alert, this connection will be invalidated such that data_from_wire and data_from_application will raise :class:`InvalidatedError`.
        Note that any incomplete data in the input may be buffered by the implementation until further calls to data_from_wire complete the messages.

    .. method:: data_from_application(output)

        :param bytes output:
            Application data to encrypt and send over the transport.
        :raises InvalidatedError:
            When the connection has been invalidated due to a previous error.

        Given plaintext application data, invoke the write callback with the encrypted data.

    .. method:: send_alert(alert_code, level=None)

        :param alert_code:
            The alert code to send in a TLS Alert message. Must be one of the constants specified in this module (TBD).
        :param level:
            Must be ALERT_WARNING or ALERT_FATAL.
            If not specified, a default will be specified based on alert_code if the TLS specification mandates a particular level for the code.
        :raises InvalidAlertLevel:
            When an alert_code is passed that is incompatible with the passed level.

        Invoke the write callback with a TLS alert message.
        Usually this is invoked automatically by a method like data_from_wire, but it may be useful to call this in your verify_callback.
        If the level is passed, the alert code *must* be compatible according to the TLS spec, otherwise :class:`InvalidAlertLevel` will be raised.
        If the level is not passed and the alert code is ambiguous according to the spec, :class:`InvalidAlertLevel` will also be raised in this case.
        Certain send_alert() calls may invalidate the connection, in which case further calls to data_from_application and data_from_wire will fail with :class:`InvalidatedError`.

    .. method:: application_finished()

        Indicate that the application is finished sending data to ``data_from_application``.
        If the connection has already started, this will invoke the write callback with a TLS Finished message.



Certificate APIs
================

Definition: a "leaf" certificate is a non-CA certificate.

.. class:: Certificate

    .. method:: get_asn1_bytes()

        Get the ASN1-format bytes of the certificate.

.. class:: ClientCertificateStore

    .. method:: get_certificate_chain_for_roots(roots, certificate_chain_callback)

        :param set roots:
            A set of keyless certificate that the server specified as the valid roots that a client certificate must chain to.

        :param callable certificate_chain_callback:
            The callback that this method should eventually invoke to specify the client certificates to send.

        This method is intended to be implemented by the user, NOT called by the user.

        Get the client certificate chain to send to the server, based on the roots specified by the server.
        The result should be specified by calling certificate_chain_callback.
        It must be passed either a single certificate chain (with ONE leaf certificate that MUST have a private key), or None to indicate no client certificates are available.

        The certificates must chain to one of the roots specified by the server, or :class:`NoCertificateChainError` will be raised.
        Invoking this callback more than once will result in :class:`InvalidatedError` being raised.
        The callback may also raise :class:`LeafCertificateHasNoPrivateKeyError`, :class:`MoreThanOneLeafCertificateError`, or :class:`NoLeafCertificateError`.

    .. method:: get_default_certificate_chain(certificate_chain_callback)

        :param callable certificate_chain_callback:
            The callback that this method should eventually invoke to specify the client certificates to send.

        This method is intended to be implemented by the user, NOT called by the user.

        Get the default client certificate in the case that the server did not provide roots that the client certificate must chain to.
        The result should be specified by calling certificate_chain_callback.
        It must be passed either a single certificate chain (with ONE leaf certificate that MUST have a private key), or None to indicate no client certificates are available.

        Invoking this callback more than once will result in :class:`InvalidatedError` being raised.
        The callback may also raise :class:`LeafCertificateHasNoPrivateKeyError`, :class:`MoreThanOneLeafCertificateError`, or :class:`NoLeafCertificateError`.

.. class:: TrustStore(certificates)

    :param set certificates:
        A set of Certificate objects, none of which may have private keys.

    Create a store of trusted CA certificates to be used with ClientTLS. No methods are public.
    If any private keys are found in any of the certificates, :class:`ExtraneousPrivateKeyError` will be raised.

.. class:: ServerCertificates

    An abstract base class representing the type of operations possible on a collection of server certificates.

    .. method:: get_certificate_chain_for_server_name(server_name, certificate_chain_callback)

        :param bytes server_name:
            The server name.
        :param callable certificate_chain_callback:
            A callable of one argument that must be eventually called by this method.

        This method is intended to be implemented by the user, NOT called by the user.

        Get the server chain to send to the client when the client is using Server Name Indication (SNI).
        Implement this method to invoke the certificate_chain_callback with a collection of certificates with ONE leaf certificate that MUST have a private key.
        None may be passed to the certificate_chain_callback in case no certificates can be found, in which case a TLS Alert will be sent.
        Passing a "default" certificate chain that doesn't match the server name is acceptable.

        Invoking this callback more than once will result in :class:`InvalidatedError` being raised.
        The callback may be invoked at any point after this method is invoked; it needn't be invoked synchronously.
        The callback may also raise :class:`LeafCertificateHasNoPrivateKeyError`, or :class:`NoLeafCertificateError`.

.. class:: ServerCertificateChain(chain)

    provides ServerCertificates

    :param set chain:
        A single chain of certificates, the leaf of which MUSt have a private key.

    Specify the certificate chain that will be sent to all clients.

.. class:: SNIServerCertificates(certificates, default=set())

    provides ServerCertificates

    :param set certificates:
        A set of certificates that may contain multiple distinct certificate chains.
        Any leaf certificates MUST have private keys.
    :param set default:
        A single certificate chain, the leaf of which MUST have a private key.

    Represents a SNI-capable set of certificates for use with ServerTLS.


Exceptions
==========

.. class:: TLSAlertError

    :attribute alert_code: code of the alert
    :attribute alert_level: level of the alert

    Raised when a TLS Alert message was received from the peer.

.. class:: BadTLSDataError

    Raised when invalid TLS data was received from the peer.

.. class:: InvalidatedError

    Raised when it's no longer valid to call a method or callback based on previous state.
    e.g., a certificate_chain_callback from :class:`ServerCertificates.get_certificate_chain_for_server_name` being invoked a second time, or :class:`Connection.data_from_wire` being invoked after a connection has been invalidated due to incorrect data.

.. class:: InvalidAlertLevel

    Raised when an alert code is not allowed to have the specified alert level.

.. class:: LeafCertificateHasNoPrivateKeyError

    Raised when the leaf certificate doesn't have a private key.

.. class:: MoreThanOneLeafCertificateError

    Raised when there's more than one leaf certificate in a set of certificates.

.. class:: NoLeafCertificateError

    Raised when there are no leaf certificates in a set of certificates.
    A "leaf" is defined as a non-CA certificate.

.. class:: NoCertificateChainError

    A certificate chain cannot be found between a specified leaf and a specified root.

.. class:: ExtraneousPrivateKeyError

    A private key was found associated with a certificate when it shouldn't have been.

TODO
====

- Certificates

  - TODO: design factories for building sets or chains of certificates from PEM
    files that are strict about:

    - private keys where they don't belong, or lack of private keys where we
      should have them

    - chain files that have things that aren't a part of the chain

- Determine better names for methods

- look through the past ten years of CVEs on OpenSSL, SecureTransport, GnuTLS,
  PolarSSL, etc.

  - old TLS Finished security flaw, having to do with half-closed sockets.
  - timing attacks:
    http://armoredbarista.blogspot.de/2014/04/easter-hack-even-more-critical-bugs-in.html

- Determine if the TLS implementation needs a clock (are there specific
  timeouts we need to wait for, etc).

  - look up what the requirements for responding to a handshake. scenario:
    client sends ClientHello (to renegotiate), server already had a huge amount
    of data in its write buffer. how long should client wait to receive
    ServerHello?

- add a method to ServerCertificates for non-SNI case

  - Actually, I don't think we need one yet. What's the use case for dynamic
    lookup of *non*-SNI server certificates?

- alerts

  - perhaps alert() should be removed.

  - figure out which TLS Alerts actually matter.

  - make alert take constants for level and code instead of integers.

- pin against port and host (???)

- connections should probably have a .cipher_suite, .tls_version, .session_id,
  .tls_extensions, and lots more

- allow disabling certain options (tls versions or algorithm choices) that we
  know are less secure than mandatory options.


- alternative cert validation support such as DANE or TACK.

Future Work
===========

- Session resumption:

  - ensure there's a solid way to invalidate session-resumption data on receipt
    of an alert (on both client and server)

- maybe allow clients to request renegotiation, if there are good use cases.

- maybe allow servers to request renegotiation, if there are good use cases.

- Is there a use case for making dh_params per-server-cert-chain in the SNI
  case? Some rumblings in this area, but no clear reason.
