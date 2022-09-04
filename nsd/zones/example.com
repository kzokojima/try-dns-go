$ORIGIN example.com.
$TTL 3600

; SOA
; SOA record should be on one line to use provided helper scripts
@   IN   SOA   ns1.example.com. hostmaster.example.com. 2016020202 7200 1800 1209600 86400

; NAMESERVERS
@                   IN                NS                   ns1.example.com.
@                   IN                NS                   ns2.example.com.

; A RECORDS
@                   IN                A                    192.0.2.1
www                 IN                CNAME                @
mail1               IN                A                    192.0.2.2
mail2               IN                A                    192.0.2.3
@                   IN                MX                   10 mail1
@                   IN                MX                   20 mail2
@                   IN                TXT                  foo
@                   IN                AAAA                 2001:db8::1
long                IN                TXT                  12345678901234567890123456789012345678901234567890
long                IN                TXT                  23456789012345678901234567890123456789012345678901
long                IN                TXT                  34567890123456789012345678901234567890123456789012
long                IN                TXT                  45678901234567890123456789012345678901234567890123
long                IN                TXT                  56789012345678901234567890123456789012345678901234
long                IN                TXT                  67890123456789012345678901234567890123456789012345
long                IN                TXT                  78901234567890123456789012345678901234567890123456
long                IN                TXT                  89012345678901234567890123456789012345678901234567
long                IN                TXT                  90123456789012345678901234567890123456789012345678
long                IN                TXT                  01234567890123456789012345678901234567890123456789
