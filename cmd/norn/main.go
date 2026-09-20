// Command norn is the operator CLI.
//
// Every command that inspects a log does so as a verifier would: it is handed
// a trust anchor out of band and refuses to conclude anything the anchor does
// not support. There is deliberately no flag to skip verification.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	run, ok := commands[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "norn: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, "norn:", err)
		os.Exit(1)
	}
}

type command func(args []string) error

var commands = map[string]command{
	"enroll":          enrollCmd,
	"init":            initCmd,
	"sign":            signCmd,
	"status":          statusCmd,
	"submit":          submitCmd,
	"verify":          verifyCmd,
	"verify-evidence": verifyEvidenceCmd,
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: norn <command> [flags]

commands:
  enroll   build a signed enrollment request for this device (SPEC §16)
  init     create a network: roots, thresholds, genesis and the trust file
  sign     verify a request and sign the enroll entry it asks for
  status   what this node can prove about the network right now
  submit   send a signed entry to the log and keep its receipt
  verify   fetch a log, check it against a trust anchor, and report its state

  verify-evidence
           check a fork evidence file offline, against a trust anchor alone

Run "norn <command> -h" for a command's flags.
`)
}

// newFlagSet returns a flag set that prints to stderr and does not os.Exit on
// its own, so the caller decides what a usage error means.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("norn "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
