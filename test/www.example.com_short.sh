args='www.example.com +short'
expected=$(cat << EOS
example.com.
192.0.2.1
192.0.2.2
EOS
)
actual=$(${CMD} ${args})
assert_equals "${expected}" "${actual}"
