resolver
============

.. contents::

试玩
------------
.. code:: bash
    
    # macOS
    wget "https://github.com/ExodusVPN/resolver/releases/download/v0/resolver-darwin"
    chmod +x resolver-darwin
    ./resolver-darwin


Build
---------------
.. code:: bash

    git clone https://github.com/ExodusVPN/resolver
    cargo build --release

    cargo run --release



协议特性支持
------------
*   ✅ IDN (Internationalized Domain Name)
*   ✅ DNS Message compression
*   ✅ DNSSEC (DNS Security Extension)
*   ✅ ECS (EDNS Client Subnet)


传输层协议支持
---------------
*   ✅ DNS Transport over UDP
*   ✅ DNS Transport over TCP
*   🔜 DNS over TLS (DoT)
*   🔜 DNS over HTTPS (DoH)
*   🔜 DNSCrypt over UDP
*   🔜 DNSCrypt over TCP


RFC 实现
-----------
*   ✅ `[RFC1035] DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION <https://tools.ietf.org/html/rfc1035>`_
*   ✅ `[RFC2535] Domain Name System Security Extensions <https://tools.ietf.org/html/rfc2535>`_
*   ✅ `[RFC2671] Extension Mechanisms for DNS (EDNS0) <https://tools.ietf.org/html/rfc2671>`_
*   ✅ `[RFC4034] Resource Records for the DNS Security Extensions <https://tools.ietf.org/html/rfc4034>`_
*   ✅ `[RFC4035] Protocol Modifications for the DNS Security Extensions <https://tools.ietf.org/html/rfc4035>`_
*   ✅ `[RFC4509] Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs) <https://tools.ietf.org/html/rfc4509>`_
*   ✅ `[RFC5155] DNS Security (DNSSEC) Hashed Authenticated Denial of Existence <https://tools.ietf.org/html/rfc5155>`_
*   ✅ `[RFC6891] Extension Mechanisms for DNS (EDNS(0)) <https://tools.ietf.org/html/rfc6891>`_
*   ✅ `[RFC7766] DNS Transport over TCP - Implementation Requirements <https://tools.ietf.org/html/rfc7766>`_


