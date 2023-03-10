args='example.com A'
expected=$(cat << EOS
;; QUESTION SECTION:
;example.com. IN A

;; ANSWER SECTION:
example.com. 600 IN A 192.0.2.1
example.com. 600 IN A 192.0.2.2

;; AUTHORITY SECTION:
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.
EOS
)
actual=$(${CMD} ${args} | grep -Fx -A $(echo "$expected" | wc -l) ';; QUESTION SECTION:')
assert_equals "${expected}" "${actual}"
