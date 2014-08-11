tls
===

A pure-Python implementation of TLS 1.2, using `PyCA's Cryptography`_ for all
cryptographic primitives (e.g. ``AES``, ``RSA``, etc.).

This is still very incomplete, and under active development.

Some of the basic tenets predicating the design:

- It will be be easy to use!
- It will be opinionated about which math and TLS versions to use, and not allow downgrading to weaker security
- It will have no IO (deal only with in-memory buffers)
- It will be implemented with multiple backends, such as OpenSSL, SecureTransport, PyTLS, etc.
- It will have no global state
- It will not allow disabling of security features such as basic security checks, chain validation and hostname validation.
- It will support both client and server operation.
- We may expose less safe and more flexible lower-level APIs, but they will be clearly delineated from the API that people *should* be using.

In addition, we may implement the protocol from scratch (of course using existing cryptography backends) in the future.

.. _`PyCA's Cryptography`: https://cryptography.io/
