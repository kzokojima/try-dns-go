# DNS lookup utility

## Build

```
$ go build
```

## Test

```
$ ./test.sh
```

## Run

```
$ ./try-dns-go @1.1.1.1 example.com A
$ ./try-dns-go @1.1.1.1 www.example.com A
$ ./try-dns-go @1.1.1.1 example.com NS
$ ./try-dns-go @1.1.1.1 example.com MX
$ ./try-dns-go @1.1.1.1 example.com TXT
$ ./try-dns-go @1.1.1.1 example.com AAAA
$ ./try-dns-go @1.1.1.1 -x 1.1.1.1
$ ./try-dns-go @1.1.1.1 -x 2606:4700:4700::1111
```

## Develop

Zone files: `nsd/zones/*.zone`

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
$ go run . @127.0.0.1 -p 8053 example.com
```

## References

* [RFC 1034 Domain names - concepts and facilities](https://www.rfc-editor.org/info/rfc1034)
* [RFC 1035 Domain names - implementation and specification](https://www.rfc-editor.org/info/rfc1035)
* [RFC 6891 Extension Mechanisms for DNS (EDNS(0))](https://www.rfc-editor.org/info/rfc6891)
* [JPRS DNS関連技術情報#DNS関連のRFC](https://jprs.jp/tech/index.html#dns-rfc-info)
* [DNSパケットフォーマットと、DNSパケットの作り方](https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html)
