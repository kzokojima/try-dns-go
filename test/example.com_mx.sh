args='example.com MX'
expected=$(cat << EOS
;; QUESTION SECTION:
;example.com. IN MX

;; ANSWER SECTION:
example.com. 3600 IN MX 10 mx1.example.com.
example.com. 3600 IN MX 20 mx2.example.com.

;; AUTHORITY SECTION:
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.

;; ADDITIONAL SECTION:
mx1.example.com. 3600 IN A 192.0.2.3
mx2.example.com. 3600 IN A 192.0.2.4
mx1.example.com. 3600 IN AAAA 2001:db8::3
mx2.example.com. 3600 IN AAAA 2001:db8::4
EOS
)
actual=$(${CMD} ${args} | grep -Fx -A $(echo "$expected" | wc -l) ';; QUESTION SECTION:')
assert_equals "${expected}" "${actual}"
