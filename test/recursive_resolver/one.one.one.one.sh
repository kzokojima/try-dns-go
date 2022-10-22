args='one.one.one.one'
expected=$(cat << EOS
;; ANSWER SECTION:
one.one.one.one.	300	IN	A	1.0.0.1
one.one.one.one.	300	IN	A	1.1.1.1
EOS
)
actual=$(${CMD} ${args} | grep -Fx -A $(echo "$expected" | wc -l) ';; ANSWER SECTION:' | sort)
assert_equals "${expected}" "${actual}"
