Contributing
============

As an open source project, ``TLS`` welcomes contributions of many forms.

Examples of contributions include:

* Code patches
* Documentation improvements
* Bug reports and patch reviews

Contributing guidelines
-----------------------

* Always make a new branch for your work.
* Keep patches small to make reviewing easier. A good rule of thumb is no more
  than 300 lines of code.
* Follow `PEP 8`_. `flake8`_ is a useful tool for making sure your code
  complies with PEP 8.
* Every code file must start with the boilerplate notice of the Apache
  License. Additionally, every Python code file must contain

  .. code-block:: python

    from __future__ import absolute_import, division, print_function

* Ensure your code is tested and documented. Patches without 100% test coverage
  or documentation will not be accepted.
* Write `good commit messages`_.

Merge requirements
------------------

To minimize the chances of bugs in ``TLS``,  we follow a strict merge policy
for committers:

* Patches must *never* be pushed directly to ``master``, all changes (even the
  most trivial typo fixes!) must be submitted as a pull request.
* A committer may *never* merge their own pull request, a second party must
  merge their changes. If multiple people work on a pull request, it must be
  merged by someone who did not work on it.
* A patch that breaks tests, or introduces regressions by changing or removing
  existing tests should not be merged. Tests must always be passing on
  ``master``.
* If somehow the tests get into a failing state on ``master`` (such as by a
  backwards incompatible release of a dependency) no pull requests may be
  merged until this is rectified.
* All merged patches must have 100% test coverage.

Licensing
---------

You must have legal permission to distribute any code you contribute to
``tls``, and it must be available under both the BSD and Apache
Software License Version 2.0 licenses.


.. _`PEP 8`: http://legacy.python.org/dev/peps/pep-0008/
.. _`flake8`: https://flake8.readthedocs.io/en/2.1.0/
.. _`good commit messages`: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
.. _`squash`: http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html
