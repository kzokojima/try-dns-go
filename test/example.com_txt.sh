args='example.com TXT'
expected=$(cat << EOS
;; QUESTION SECTION:
;example.com. IN TXT

;; ANSWER SECTION:
example.com. 3600 IN TXT "foo" "bar"

;; AUTHORITY SECTION:
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.
EOS
)
actual=$(${CMD} ${args} | grep -Fx -A $(echo "$expected" | wc -l) ';; QUESTION SECTION:')
assert_equals "${expected}" "${actual}"
