resolver
============

.. contents::


测试
--------

.. code:: bash
    
    cargo run --example dig baidu.com
    cargo run --example dig 互联网中心.中国


特性
-------
*   支持国际化域名的直接查询 (非 ASCII 域名)
*   完整支持 DNS Message compression。


协议支持
----------

*   ✅ DNS Transport over UDP
*   ✅ DNS Transport over TCP
*   🔜 DNS Security Extension (DNSSEC)
*   🔜 EDNS Client Subnet (ECS)
*   🔜 DNS over TLS (DoT)
*   🔜 DNS over HTTPS (DoH)
*   🔜 DNSCrypt

RFC 实现
-----------

*   ✅ `[RFC1035] DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION <https://tools.ietf.org/html/rfc1035>`_
*   🔜 `[RFC2671] Extension Mechanisms for DNS (EDNS0) <https://tools.ietf.org/html/rfc2671>`_
*   🔜 `[RFC6891] Extension Mechanisms for DNS (EDNS(0)) <https://tools.ietf.org/html/rfc6891>`_
*   🔜 `[RFC7766] DNS Transport over TCP - Implementation Requirements <https://tools.ietf.org/html/rfc7766>`_


DNS安全问题
------------

*   `DNSSEC ‘and’ DNS over TLS <https://blog.apnic.net/2018/08/20/dnssec-and-dns-over-tls/>`_ , By Geoff Huston on 20 Aug 2018
*   `TLD DNSSEC Report (2019-10-01 00:02:47) <http://stats.research.icann.org/dns/tld_report/>`_


感兴趣的实现
------------
*   `[RFC1035] DNS Transport over UDP <https://tools.ietf.org/html/rfc1035>`_
*   `[RFC7766] DNS Transport over TCP <https://tools.ietf.org/html/rfc7766>`_
*   `[RFC2535] DNSSEC <https://tools.ietf.org/html/rfc2535>`_
*   `[RFC7858] DNS over Transport Layer Security (TLS) <https://tools.ietf.org/html/rfc7858>`_
*   `[RFC8484] DNS Queries over HTTPS (DoH) <https://tools.ietf.org/html/rfc8484>`_ ， 兴趣不大
*   `DNSCrypt <https://github.com/DNSCrypt/dnscrypt-protocol>`_


