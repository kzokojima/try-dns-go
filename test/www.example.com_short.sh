args='www.example.com'
expected=$(cat << EOS
example.com.
192.0.2.1
EOS
)
actual=$(${CMD} ${args} +short)
assert_equals "${expected}" "${actual}"
