open-quantum-safe XMSS integration - 2018-03-06
===============================================

[Original open-quantum-safe/openssl README below.]

This is an experimental integration of the XMSS hash-based signature scheme
into open-quantum-safe/openssl, based on
https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/
with additional S/MIME support.

Integration based on the XMSS Internet-Draft reference implementation from
http://www.pqsignatures.org/index/publications.html#code

This code does not include optimised authentication path computation such as
the BDS algorithm.

A more mature security library integration of XMSS can be found in official
Bouncy Castle Java releases: https://www.bouncycastle.org/java.html

Instructions
-------------

	chmod +x config

	./config -debug -g -ldl -fPIC -DPURIFY

	make depend

	cd vendor/liboqs/

	make

	cd ../..

	make

	cd vendor/liboqs/src/xmss/

	./newcert_xmss.sh

The previous script will generate an XMSS (self-signed) certificate and the
corresponding keys.

	sudo ./ssl_server sk_xmss.pem cert_xmss.pem 443

In a separate terminal, while the server is still running, run the test client
like so:

	./ssl_client http://localhost:443


[Original open-quantum-safe/openssl README starts next line.]
==========================================================

open-quantum-safe/openssl
=========================

OpenSSL is an open-source TLS/SSL and crypto library [https://openssl.org/](https://openssl.org/).  ([View the original README file for OpenSSL](https://github.com/open-quantum-safe/openssl/blob/OpenSSL_1_0_2-stable/README).)

This repository contains a fork of OpenSSL that adds quantum-safe cryptographic algorithms and ciphersuites.

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  liboqs initially focuses on key exchange algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into OpenSSL 1.0.2.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Contents
--------

open-quantum-safe/openssl currently contains:

- Integration of post-quantum key exchange primitives from liboqs into OpenSSL's `speed` command
- Ciphersuites using post-quantum key exchange based on primitives from liboqs, including hybrid ciphersuites which also use ECDHE key exchange

Our modifications are **only** for OpenSSL v1.0.2, and appear only on the [OpenSSL\_1\_0\_2-stable branch](https://github.com/open-quantum-safe/openssl/tree/OpenSSL_1_0_2-stable).

### Key exchange mechanisms

liboqs currently supports the following key exchange mechanisms:

- `RLWE_BCNS15`: key exchange from the ring learning with errors problem (Bos, Costello, Naehrig, Stebila, *IEEE Symposium on Security & Privacy 2015*, [https://eprint.iacr.org/2014/599](https://eprint.iacr.org/2014/599))
- `RLWE_NEWHOPE`: "NewHope": key exchange from the ring learning with errors problem (Alkim, Ducas, Pöppelmann, Schwabe, *USENIX Security 2016*, [https://eprint.iacr.org/2015/1092](https://eprint.iacr.org/2015/1092)) (using the reference C implementation of NewHope from [https://github.com/tpoeppelmann/newhope](https://github.com/tpoeppelmann/newhope))
- `LWE_FRODO_RECOMMENDED`: "Frodo": key exchange from the learning with errors problem (Bos, Costello, Ducas, Mironov, Naehrig, Nikolaenko, Raghunathan, Stebila, *ACM Conference on Computer and Communications Security 2016*, [http://eprint.iacr.org/2016/659](http://eprint.iacr.org/2016/659)); using the "recommended" parameter set

### Ciphersuites

For each post-quantum key exchange primitive `X`, there are the following ciphersuites:

- `X-RSA-AES128-GCM-SHA256`
- `X-ECDSA-AES128-GCM-SHA256`
- `X-RSA-AES256-GCM-SHA384`
- `X-ECDSA-AES256-GCM-SHA384`
- `X-ECDHE-RSA-AES128-GCM-SHA256`
- `X-ECDHE-ECDSA-AES128-GCM-SHA256`
- `X-ECDHE-RSA-AES256-GCM-SHA384`
- `X-ECDHE-ECDSA-AES256-GCM-SHA384`

There is also a "generic" ciphersuite (`X` = `GENERIC`) which uses whichever key exchange primitive is configured as the default key exchange primitive in liboqs.  It is set to `GENERIC` = `RLWE_BCNS15`, but this can be changed.


Building
--------

Builds have been tested on Mac OS X 10.11.6, macOS 10.12, Ubuntu 16.04.1, and Windows 10.

### Linux and macOS

To build, clone or download the source from Github:

	git clone --branch OpenSSL_1_0_2-stable https://github.com/open-quantum-safe/openssl.git
	cd openssl

To configure OpenSSL, on Linux type:

	./config
	
and on Mac OS X type:

	./Configure darwin64-x86_64-cc
	
Then type:

	make depend
	make
	
This will build both liboqs and OpenSSL.  

### Windows

Windows binaries can be generated using the standard build process for OpenSSL on Windows.

Running
-------

See the [liboqs Github site](https://github.com/open-quantum-safe/liboqs/) for information on test programs in liboqs.

### openssl speed

OpenSSL's `speed` command performs basic benchmarking of cryptographic primitives.  You can see results for primitives from liboqs by typing

	apps/openssl speed oqskex

### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.

To see the list of supported ciphersuites from OQS, type:

	apps/openssl ciphers OQSKEX-GENERIC:OQSKEX-GENERIC-ECDHE:OQSKEX-RLWE-BCNS15:OQSKEX-RLWE-BCNS15-ECDHE:OQSKEX-RLWE-NEWHOPE:OQSKEX-RLWE-NEWHOPE-ECDHE:OQSKEX-LWE-FRODO-RECOMMENDED:OQSKEX-LWE-FRODO-RECOMMENDED-ECDHE

To run a server, we first need to generate a self-signed X.509 certificate.  Run the following command:

	apps/openssl req -x509 -new -newkey rsa:2048 -keyout server.key -nodes -out server.cer -sha256 -days 365 -config apps/openssl.cnf

Hit enter in response to all the prompts to accept the defaults.  

When done, type to combine the key and certificate (as required by `s_server`):

	cat server.key server.cer > server.pem

To run a basic TLS server with all OQS ciphersuites enabled:

	apps/openssl s_server -cipher OQSKEX-GENERIC:OQSKEX-GENERIC-ECDHE:OQSKEX-RLWE-BCNS15:OQSKEX-RLWE-BCNS15-ECDHE:OQSKEX-RLWE-NEWHOPE:OQSKEX-RLWE-NEWHOPE-ECDHE:OQSKEX-LWE-FRODO-RECOMMENDED:OQSKEX-LWE-FRODO-RECOMMENDED-ECDHE

In another terminal window, you can run a TLS client for any or all of the supported ciphersuites, for example:

	apps/openssl s_client -cipher OQSKEX-GENERIC
	apps/openssl s_client -cipher OQSKEX-GENERIC-ECDHE
	apps/openssl s_client -cipher OQSKEX-RLWE-BCNS15
	apps/openssl s_client -cipher OQSKEX-RLWE-BCNS15-ECDHE
	apps/openssl s_client -cipher OQSKEX-RLWE-NEWHOPE
	apps/openssl s_client -cipher OQSKEX-RLWE-NEWHOPE-ECDHE
	apps/openssl s_client -cipher OQSKEX-LWE-FRODO-RECOMMENDED
	apps/openssl s_client -cipher OQSKEX-LWE-FRODO-RECOMMENDED-ECDHE

Current status and plans
------------------------

Our initial launch of the liboqs integration into OpenSSL was on August 25, 2016.  

At this point, there are no plans to add further functionality to the OpenSSL integration, beyond supporting additional algorithms added by liboqs.  See the [liboqs](https://github.com/open-quantum-safe/liboqs/#current-status-and-plans) page for more information about liboqs plans.  Update: we realize there is interest in quantum-safe signature integration in OpenSSL, and will consider this when we begin to add signature schemes to liboqs; volunteers welcome!

We will endeavour to regularly sync our branch with commits in the original openssl/openssl repository.

For future reference, adding new algorithms/ciphersuites can easily be done by following these diffs:

- apps/speed: [commit cb91c708b8bec35284054562295d6b9adff76d2a](https://github.com/open-quantum-safe/openssl/commit/cb91c708b8bec35284054562295d6b9adff76d2a)
- ssl: [commit 3a04b822b317ac548933c10974bea638086cf29e](https://github.com/open-quantum-safe/openssl/commit/3a04b822b317ac548933c10974bea638086cf29e)

Note
----

Proofs of TLS such as [[JKSS12]](https://eprint.iacr.org/2011/219) and [[KPW13]](https://eprint.iacr.org/2013/339) require a key exchange mechanism that has a form of active security, either in the form of the PRF-ODH assumption, or an IND-CCA KEM.  Most basic post-quantum key exchange mechanisms do not achieve active security, and would need to have an IND-CPA to IND-CCA KEM transform applied [[Pei14]](https://eprint.iacr.org/2014/070) or be protected from active attacks using a signature scheme [[BCNS15]](https://eprint.iacr.org/2014/599).  Neither countermeasure is currently applied in this prototype OpenSSL integration, so existing proofs of security of TLS against active attackers do not apply to this software.  Improving this is an active research goal.

License
-------

All modifications in the open-quantum-safe/openssl repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](https://github.com/open-quantum-safe/openssl/blob/OpenSSL_1_0_2-stable/LICENSE).  

Team
----

The Open Quantum Safe project is lead by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (McMaster University).

### Support

Development of Open Quantum Safe has been supported in part by the Tutte Institute for Mathematics and Computing.  Research projects which developed specific components of Open Quantum Safe have been supported by various research grants; see the source papers for funding acknowledgements.
