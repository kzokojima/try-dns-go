# DNS lookup utility

## Build

```
$ ./build.sh
```

## Test

```
$ ./test.sh
```

## Run

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
$ go run ./cmd/lookup @127.0.0.1 -p 8053 example.com
```

## References

* [RFC 1034 Domain names - concepts and facilities](https://www.rfc-editor.org/info/rfc1034)
* [RFC 1035 Domain names - implementation and specification](https://www.rfc-editor.org/info/rfc1035)
* [RFC 4034 Resource Records for the DNS Security Extensions](https://www.rfc-editor.org/info/rfc4034)
* [RFC 4035 Protocol Modifications for the DNS Security Extensions](https://www.rfc-editor.org/info/rfc4035)
* [RFC 6891 Extension Mechanisms for DNS (EDNS(0))](https://www.rfc-editor.org/info/rfc6891)
* [JPRS DNS関連技術情報#DNS関連のRFC](https://jprs.jp/tech/index.html#dns-rfc-info)
* [DNSパケットフォーマットと、DNSパケットの作り方](https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html)
