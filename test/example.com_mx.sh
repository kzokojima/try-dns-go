args='example.com MX'
expected=$(cat << EOS
;; QUESTION SECTION:
;example.com. IN MX
;; ANSWER SECTION:
example.com. 3600 IN MX 10 mail1.example.com.
example.com. 3600 IN MX 20 mail2.example.com.
;; AUTHORITY SECTION:
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.
;; ADDITIONAL SECTION:
mail1.example.com. 3600 IN A 192.0.2.2
mail2.example.com. 3600 IN A 192.0.2.3
EOS
)
actual=$(${CMD} ${args} | grep -Fx -A 100 ';; QUESTION SECTION:')
assert_equals "${expected}" "${actual}"
