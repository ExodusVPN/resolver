resolver
============

.. contents::

测试
--------

.. code:: bash
    
    # macOS
    brew install pkg-config openssl
    # Debian/Ubuntu
    sudo apt install pkg-config libssl-dev
    # Fedora
    sudo dnf install pkg-config openssl-devel
    
    cargo build --example dig
    cargo run --example dig 8.8.8.8:53 baidu.com
    cargo run --example dig 8.8.8.8:53 gov.cn
    cargo run --example dig 8.8.8.8:53 www.gov.cn
    cargo run --example dig 8.8.8.8:53 互联网中心.中国

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


DNSSEC 在根域名和顶级域名服务器当中的部署情况
--------------------------------------------
所有的根域名服务器都支持 DNSSEC 特性。

*   `TLD DNSSEC Report <http://stats.research.icann.org/dns/tld_report/>`_ , 该报告会每天更新一次
*   `[Wikipedia/EN] List of Internet Toplevel domains <https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains>`_


EDNS Client Subnet 在公共域名服务器当中的支持情况
----------------------------------------------
*   `Google Public DNS <https://dns.google.com/>`_
*   `GeekDNS <https://www.233py.com/#home>`_

.. NOTE:: 
    
    Cloudflare 的公共免费DNS服务出于隐私的考量，不会向 权威名称服务器 发送 任何的客户端信息（包括 EDNS Client Subnet Header ）。
    声明链接: https://developers.cloudflare.com/1.1.1.1/nitty-gritty-details/

另外，腾讯的 DNSPod 公共查询服务官网声称支持 Client Subnet 特性，但是由于该 DNS 服务不支持 DNS over TCP 协议，所以不确定是否真的支持。


KSK 轮转：常见问题与解答
---------------------------

链接: https://www.apnic.net/wp-content/uploads/2017/04/ksk-rollover-questions-answers-31oct16-zh.pdf

根区密钥签名密钥 (KSK) 轮转: https://www.icann.org/resources/pages/ksk-rollover-2016-07-28-zh


DNSSEC 信任锚自动更新机制:

`Automated Updates of DNS Security (DNSSEC) Trust Anchors <https://tools.ietf.org/html/rfc5011>`_

当前的信任锚文件下载: https://data.iana.org/root-anchors/


创建或维护 DNSSEC 验证软件的软件开发人应确保软件符合 RFC5011。


对于不符合 RFC5011 的软件，或配置为不使用 RFC5011 的软件，点击此处可获得发布流信任锚文件。
一旦开始轮转且 DNS 根区中 DNSKEY RRset 的 KSK 发生变更，即应检索文件。


软件开发人和验证解析器运营商可进行ICANN 开发的运营测试，评估其系统是否恰当执行 RFC5011 的要求及是否将在 KSK 轮转期间自动更新


检查 DNS 验证解析器中的当前信任锚
---------------------------------
https://www.icann.org/resources/pages/dns-resolvers-checking-current-trust-anchors-2018-06-28-zh

.. code:: bash

    dig @8.8.8.8 dnssec-failed.org A +dnssec
    # 如果响应包含以下内容：
    # ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL
    # 则说明解析器正在执行 DNSSEC 验证。（此处的 SERVFAIL 状态标识表明验证失败，这说明实际上执行了验证。）
    #
    # 相反，如果响应包含以下内容：
    # ;; ->>HEADER<<- opcode: QUERY, status: NOERROR
    # 则说明解析器没有执行 DNSSEC 验证。


一些关于DNS安全问题的文章
--------------------------
*   `DNSSEC ‘and’ DNS over TLS <https://blog.apnic.net/2018/08/20/dnssec-and-dns-over-tls/>`_ , By Geoff Huston on 20 Aug 2018
*   `DNS Value and Vulnerability <https://icannwiki.org/DNS_Value_and_Vulnerability>`_
*   `DNSSEC Statistics <https://www.internetsociety.org/deploy360/dnssec/statistics/>`_


DNS解析器预热
-------------

在解析器启动时，可以针对热门的域名进行预热查询，然后缓存结果，以增加DNS查询的响应速度。

热门的网站列表: https://en.wikipedia.org/wiki/List_of_most_popular_websites


常规顶级域名注册列表
------------------------

拿到几乎绝大部分域名的列表后，可以针对这些域名在本地进行DNS查询，判断哪些域名的查询过程被审查（使用 TCP 协议查询，被审查时，会收到 RST TCP 包）。

ccTLDs 的数据目前似乎无法拿到。

gTlDs 可以拿到，.com 和 .name 需要单独向 verisign 拿。


https://www.verisign.com/zh_CN/channel-resources/domain-registry-products/zone-file/index.xhtml?loc=zh_CN

https://czds.icann.org/zone-requests/all


感兴趣的实现
------------
*   `[RFC1035] DNS Transport over UDP <https://tools.ietf.org/html/rfc1035>`_
*   `[RFC7766] DNS Transport over TCP <https://tools.ietf.org/html/rfc7766>`_
*   `[RFC2535] DNSSEC <https://tools.ietf.org/html/rfc2535>`_
*   `[RFC7858] DNS over Transport Layer Security (TLS) <https://tools.ietf.org/html/rfc7858>`_
*   `[RFC8484] DNS Queries over HTTPS (DoH) <https://tools.ietf.org/html/rfc8484>`_ ， 兴趣不大
*   `DNSCrypt <https://github.com/DNSCrypt/dnscrypt-protocol>`_


