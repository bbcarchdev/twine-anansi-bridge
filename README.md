This project contains the bridge between [Anansi](https://bbcarchdev.github.io/anansi/) and [Twine](https://bbcarchdev.github.io/twine/). It was originally part of the Twine project and has been separated for ease of maintenance.

It consists of two things:

* A loadable module for Twine that supports `application/x-anansi-url` messages and bulk imports.
* The `twine-anansi-bridge` program, which reads from Anansi's queue database and injects into Twine's message queue (or dumps a list of URLs standard output)

Both are configured using `twine.conf`.

