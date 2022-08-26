args='example.com AAAA'
expected=$(cat << EOS
;; QUESTION SECTION:
;example.com. IN AAAA
;; ANSWER SECTION:
example.com. 3600 IN AAAA 2001:db8::1
;; AUTHORITY SECTION:
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.
EOS
)
actual=$(${CMD} ${args} | grep -Fx -A 100 ';; QUESTION SECTION:')
assert_equals "${expected}" "${actual}"
