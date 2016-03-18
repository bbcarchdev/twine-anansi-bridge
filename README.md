# Twine/Anansi Bridge
A module for [Twine](https://bbcarchdev.github.io/twine/) that supports
processing RDF stored in [Anansi’s](https://bbcarchdev.github.io/anansi/)
cache.

[![Apache 2.0 licensed][license]](#license)

## Configuration

Configuration is via the `twine.conf` configuration file. You will need to
ensure the `anansi.so` plug-in is actually loaded and add an `[anansi]` section
containing database and cache details. If your Anansi cache is stored in an S3 or
RADOS bucket, add an `[s3]` section as well.

	[twine]
	; Existing configuration values
	; ...
	plugin=anansi.so
	;; Optional: configure Twine to use the Anansi crawl queue as its
	;; message-queue source
	mq=anansi:///
	
	[anansi]
	db=mysql://anansi@localhost/anansi
	;; The cache can be a file path or an s3: bucket URL
	cache=/path/to/disk/cache
	; cache=s3://anansicache/
	
	[s3]
	verbose=no
	; endpoint=rados.localnet
	access=AKMAIQ8VZ99KR4KO9TBA
	secret=ssfvZZFgs89Ak2u4pKbCP2KljPOphiLSJP4xjA5W

When Twine is configured to use `anansi:///` as its message queue, crawled
resources in the `ACCEPTED` state (i.e., those which have been successfully
crawled and processed by Anansi itself) will be passed to Twine for processing.
If Twine is configured as part of a cluster, the Anansi message queue will
load-balance across the cluster automatically.

## License

Twine is licensed under the terms of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright © 2014-2016 BBC.

[license]: https://img.shields.io/badge/license-Apache%202.0-blue.svg
