// norn is the operator CLI. Its commands are audit, enroll, init, monitor,
// sign, stamp, status, submit, verify and verify-evidence: the commands map in
// main.go is the list, and "norn <command> -h" gives each one's flags.
//
// Two kinds of entry can be built with them: genesis, by norn init, and
// enroll, by norn enroll and then norn sign, which refuses any other type.
// There is no revoke, rotate or governance builder yet (SEC-008 in
// docs/audit/SECURITY_AUDIT.md), so the ENROLLMENT.md runbooks that need one
// cannot be followed with this tool. norn submit sends any well-formed entry
// for the network, however it was built, and replay applies it if it is valid.
package main
