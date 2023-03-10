# DNS program study

## Build

```
$ ./build.sh
```

## Test

```
$ ./test.sh
```

## Run

### lookup

```
$ bin/lookup example.com A
$ bin/lookup www.example.com A
$ bin/lookup example.com NS
$ bin/lookup example.com MX
$ bin/lookup example.com TXT
$ bin/lookup example.com AAAA
$ bin/lookup -x 1.1.1.1
$ bin/lookup -x 2606:4700:4700::1111
```

### Name server

#### Options

* -address=\<address\>:\<port\>
    * Set to the listen address and port.
* -mode=\<mode\>
    * Set the server mode. The default mode is full-service resolver. Sets the "authoritative" is authoritative server.
* -zone=\<zone file\>
    * Set the zone file. If mode is full-service resolver, specify root hints file ([IANA Root Files](https://www.iana.org/domains/root/files)).
* -root-anchors-xml=\<root-anchors-xml file\>
    * Set the root-anchors-xml file. If mode is full-service resolver, specify root trust anchor file ([IANA Root Files](https://www.iana.org/domains/root/files)).

#### Authoritative server

```
# start server
$ bin/serv -address=0.0.0.0:8053 -mode=authoritative -zone=testdata/zones/example.com.zone &

# lookup
$ dig @127.0.0.1 -p 8053 +norec example.com

# stop server
$ pkill -f 0.0.0.0:8053
```

#### Full-service resolver

```
# start server
$ bin/serv -address=0.0.0.0:8053 -zone=root_files/named.root -root-anchors-xml root_files/root-anchors.xml &

# lookup
$ dig @127.0.0.1 -p 8053 example.com

# stop server
$ pkill -f 0.0.0.0:8053
```

## Develop

Zone files: `testdata/zones/*.zone`

Local DNS server operations:

```
# Up local DNS server
$ docker compose up -d

# Restart local DNS server
$ docker compose restart

# Down local DNS server
$ docker compose down
```

Run:

```
$ go run ./cmd/lookup @127.0.0.1 -p 8053 +norec example.com
```

## References

* [RFC 1034 Domain names - concepts and facilities](https://www.rfc-editor.org/info/rfc1034)
* [RFC 1035 Domain names - implementation and specification](https://www.rfc-editor.org/info/rfc1035)
* [RFC 3110 RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)](https://www.rfc-editor.org/info/rfc3110)
* [RFC 4034 Resource Records for the DNS Security Extensions](https://www.rfc-editor.org/info/rfc4034)
* [RFC 4035 Protocol Modifications for the DNS Security Extensions](https://www.rfc-editor.org/info/rfc4035)
* [RFC 5702 Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC](https://www.rfc-editor.org/info/rfc5702)
* [RFC 6891 Extension Mechanisms for DNS (EDNS(0))](https://www.rfc-editor.org/info/rfc6891)
* [RFC 9156 DNS Query Name Minimisation to Improve Privacy](https://www.rfc-editor.org/info/rfc9156)
* [JPRS DNS??????????????????#DNS?????????RFC](https://jprs.jp/tech/index.html#dns-rfc-info)
* [DNS????????????????????????????????????DNS????????????????????????](https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html)
* [?????????????????????????????????DNS](https://dnsops.jp/event/20130719/20130719-undocumented-DNS-orange-6.pdf)
