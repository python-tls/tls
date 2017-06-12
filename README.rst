tls
===

.. image:: https://travis-ci.org/python-tls/tls.svg?branch=master
    :target: https://travis-ci.org/python-tls/tls

.. image:: https://coveralls.io/repos/python-tls/tls/badge.svg?branch=master
    :target: https://coveralls.io/r/python-tls/tls?branch=master


Introduction
============

`Transport Layer Security (TLS)` is a cryptographic protocol designed to
provide communication security over the Internet.

This is an open source Python implementation of `TLS 1.2`_, using the `Python
Cryptographic Authority's (PyCA's) Cryptography`_ libraries for all
cryptographic primitives (e.g. ``AES``, ``RSA``, etc.).

This project is not yet complete; see the "Current Status" section below for
details.

More on how the TLS handshake works can be found `here`_.


Why yet another TLS library?
============================

Many major exploits in other TLS libraries in the past have been
straightforward software bugs in the protocol implementation, not subtle bugs
in the cryptographic math; bugs which would have been impossible if these
libraries had better implementation and design decisions. This project is not
directed at cipher implementation. It is, instead, focused on a careful and
rigorously testable implementation of the protocol components of TLS. This
could then, for instance, be used by networking libraries like Twisted as a
TLS-terminating proxy.

To reiterate, this project is about providing secure implementation and
designing idiomatically secure APIs, not inventing anything in the way of how
to do the securing (i.e., not reimplementing tricky cryptographic algorithms
yet again).


Goals
=====

Some of the basic tenets predicating the design:

- It will be be easy to use!
- It will be opinionated about which ciphers and TLS versions to use, and not
  allow downgrading to weaker security.
- It will only deal with in-memory buffers.
- It will have no global state.
- It will not allow disabling of security features such as basic security
  checks, chain validation and hostname validation.
- It will support both client and server operation.
- It may expose less safe and more flexible lower-level APIs, but they will be
  clearly delineated from the API that people *should* be using.


Current Status
==============

This is still very incomplete, and under active development.

For a well designed network protocol you should be able to ask two questions,
“Are these bytes a valid message?” and “Is this message valid for my current
state?”

So, when we talk about parsing a protocol, we’re mostly talking about answering
the first question. A declarative parser makes parsing much simpler by
specifying what a valid message looks like (rather than the steps you need to
take to parse it). By saying what the protocol looks like, instead of how to
parse it, you can more easily recognize and discard invalid inputs. This
project uses the ``construct`` library for parsing TLS messages.

At the time of writing this, this project can parse most TLS messages (that
don't need any encryption, at least), and construct bytes out of these
structured messages.

When we talk about processing, we’re talking about answering the second
question. This project will use explicit state machines for the processing of
TLS messages (and thus, handshake). An explicit state machine makes processing
much simpler by specifying all the valid states and transitions and inputs that
cause those transitions. And if you do all the message parsing *before* you try
processing any messages it becomes easier to avoid strange state transitions in
your processor, transitions that could lead to bugs.

I am currently working on the "processing" of the handshake -- this is the
large major part left before I am able to make a release.


Example Use
===========
A basic design for an example usage of this library using Twisted can be `found
here`_. Note that this is **not** a self-contained working sample code, its
purpose is to just give you an idea of what it would potentially look like to
use, once the implementation is more complete.


Acknowledgements
================

Python-TLS was being developed as one of the projects under `Stripe's Open
Source Retreat`_ by Ashwini Oruganti. It also includes code and reviews from
members of the PyCA community.


Discussion
==========

You can join #python-tls on Freenode to ask questions or get involved.

.. _`Python Cryptographic Authority's`: https://github.com/pyca
.. _`Python Cryptographic Authority's (PyCA's) Cryptography`: https://cryptography.io/
.. _`TLS 1.2`: http://tools.ietf.org/html/rfc5246
.. _`here`: https://github.com/python-tls/tls/blob/master/docs/_notes/tls-handshake.rst
.. _`found here`: https://gist.github.com/ashfall/b9176874aabaafd8ce56
.. _`Stripe's Open Source Retreat`: https://stripe.com/blog/stripe-open-source-retreat
