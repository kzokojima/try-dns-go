args='long.example.com TXT'
expected=$(cat << EOS
;; QUESTION SECTION:
;long.example.com. IN TXT
;; ANSWER SECTION:
long.example.com. 3600 IN TXT "12345678901234567890123456789012345678901234567890"
long.example.com. 3600 IN TXT "23456789012345678901234567890123456789012345678901"
long.example.com. 3600 IN TXT "34567890123456789012345678901234567890123456789012"
long.example.com. 3600 IN TXT "45678901234567890123456789012345678901234567890123"
long.example.com. 3600 IN TXT "56789012345678901234567890123456789012345678901234"
long.example.com. 3600 IN TXT "67890123456789012345678901234567890123456789012345"
long.example.com. 3600 IN TXT "78901234567890123456789012345678901234567890123456"
long.example.com. 3600 IN TXT "89012345678901234567890123456789012345678901234567"
long.example.com. 3600 IN TXT "90123456789012345678901234567890123456789012345678"
long.example.com. 3600 IN TXT "01234567890123456789012345678901234567890123456789"
;; AUTHORITY SECTION:
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.
EOS
)
actual=$(${CMD} ${args} | grep -Fx -A 100 ';; QUESTION SECTION:')
assert_equals "${expected}" "${actual}"