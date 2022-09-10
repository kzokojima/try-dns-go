args='-x 192.0.2.1'
expected=$(cat << EOS
;; QUESTION SECTION:
;1.2.0.192.in-addr.arpa. IN PTR

;; ANSWER SECTION:
1.2.0.192.in-addr.arpa. 3600 IN PTR example.com.
1.2.0.192.in-addr.arpa. 3600 IN PTR www.example.com.

;; AUTHORITY SECTION:
2.0.192.in-addr.arpa. 3600 IN NS ns1.example.com.
2.0.192.in-addr.arpa. 3600 IN NS ns2.example.com.
EOS
)
actual=$(${CMD} ${args} | grep -Fx -A $(echo "$expected" | wc -l) ';; QUESTION SECTION:')
assert_equals "${expected}" "${actual}"
