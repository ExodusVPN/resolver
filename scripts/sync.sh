#!/bin/bash

cd data;

# Root Hints
curl -O http://www.internic.net/domain/named.root
curl -O http://www.internic.net/domain/named.root.md5
curl -O http://www.internic.net/domain/named.root.sig

# Root Zone File
curl -O http://www.internic.net/domain/root.zone
curl -O http://www.internic.net/domain/root.zone.md5
curl -O http://www.internic.net/domain/root.zone.sig

# Root Trust Anchor
curl -O https://data.iana.org/root-anchors/icannbundle.pem
curl -O https://data.iana.org/root-anchors/root-anchors.p7s
curl -O https://data.iana.org/root-anchors/root-anchors.xml
curl -O https://data.iana.org/root-anchors/checksums-sha256.txt

# Top-Level Domains
curl -O https://data.iana.org/TLD/tlds-alpha-by-domain.txt
curl -O https://data.iana.org/TLD/tlds-alpha-by-domain.txt.md5


curl -O http://www.internic.net/domain/last_update.txt