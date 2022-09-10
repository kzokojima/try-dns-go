args='www.example.com +short'
expected=$(cat << EOS
example.com.
192.0.2.1
EOS
)
actual=$(${CMD} ${args})
assert_equals "${expected}" "${actual}"
