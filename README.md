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
```

## Develop

Zone file: `nsd/zones/example.com`

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

* https://www.rfc-editor.org/info/rfc1034
* https://www.rfc-editor.org/info/rfc6891
* https://www.rfc-editor.org/info/rfc1035
* https://jprs.jp/tech/index.html#dns-rfc-info
* https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html
