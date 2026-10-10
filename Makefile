GO      ?= go
PKGS    := ./...

.PHONY: all test vet fmt fmt-check lint ci vectors vectors-log vectors-check ref-test tidy verify-py lab-sim

all: ci

# -timeout, because `cmd/norn` builds its binary and replays the fixture in
# every case: it takes about five minutes on a quiet machine and hit Go's
# default per-package 600s once, on a busy one. A suite that flakes under load
# teaches people to re-run rather than to read.
test:
	$(GO) test -race -count=1 -timeout 30m $(PKGS)

# This runs the simulator and reports simulated latency, not the lab's
# wall-clock measurements: GOSSIP.md section 8's lab/tests/ are the lab's
# scripts, run by make lab-test. T7 refuses results inside the source tree,
# so the default result directory is under the system's temporary directory;
# set LAB_SIM_RESULTS to keep them somewhere else.
LAB_SIM_RESULTS ?= $(or $(TMPDIR),/tmp)/norn-lab-sim
lab-sim:
	@set -eu; mkdir -p "$(LAB_SIM_RESULTS)"; \
	log=$$(mktemp "$(LAB_SIM_RESULTS)/run.XXXXXX"); \
	trap 'rm -f "$$log"' EXIT HUP INT TERM; status=0; \
	NORN_SIM_RESULTS="$(LAB_SIM_RESULTS)" $(GO) test -count=1 -v -run 'TestT[0-9]' ./internal/sim >"$$log" 2>&1 || status=$$?; \
	awk '/[.]go:[0-9]+: T[0-9].*latency: .*simulated/ { \
	  sub(/^.*[.]go:[0-9]+: /, ""); key=$$1; \
	  if (!(key in lines)) order[++n]=key; \
	  lines[key]=lines[key] (lines[key] ? "; " : "") $$0; \
	} /Simulated time proves/ { sub(/^.*[.]go:[0-9]+: /, ""); caveat=$$0 } \
	END { for (i=1; i<=n; i++) print lines[order[i]]; if (caveat) print caveat }' "$$log"; \
	if [ $$status -ne 0 ]; then cat "$$log" >&2; fi; exit $$status

vet:
	$(GO) vet $(PKGS)

fmt:
	gofmt -s -w $$(find . -name '*.go' -not -path './.git/*')

fmt-check:
	@out=$$(find . -name '*.go' -not -path './.git/*' | xargs gofmt -s -l); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@2025.1.1 $(PKGS)

tidy:
	$(GO) mod tidy

PY      ?= contrib/norn-ref/.venv/bin/python

# Regenerate test vectors from the Python reference implementation (the oracle).
vectors:
	PYTHONPATH=contrib/norn-ref $(PY) contrib/norn-ref/gen_vectors.py testdata/vectors
	python3 -I testdata/vectors/ed25519-cctv/gen_cases.py

# The suite has two provenances (SPEC 12): the entry, state and trust vectors
# come from the Python reference, and the served log and proof bundles come
# from the Go implementation, because producing a tiled log needs one. Each
# half is checked against its own generator; neither is checked against itself
# alone, since upstream libraries validate both.
GO_VECTOR_DIRS := served served-large proofs fork checkpoints-bad proofs-bad served-bad served-rotated served-superseded served-twice-cosigned served-extra-witness served-name-collision served-unknown-algorithm detect served-genesis proofs-rotated

# Vectors neither of Norn's implementations produces. `anchors` holds a `.ots`
# written by python-opentimestamps, and regenerating it would defeat the point
# of having it: it is in the suite because somebody else's code wrote the bytes.
# `ed25519-cctv` likewise keeps upstream bytes; docclaims guards its derived table.
FOREIGN_VECTOR_DIRS := anchors ed25519-cctv

# Regenerate the served log and proof bundles from the Go implementation.
vectors-log:
	$(GO) run ./cmd/norn-genlog testdata/vectors

# The committed vectors ARE the contract. Prove each half is exactly what its
# generator produces. Without this a stale file can survive indefinitely --
# seven once did.
vectors-check:
	@tmp=$$(mktemp -d); \
	PYTHONPATH=contrib/norn-ref $(PY) contrib/norn-ref/gen_vectors.py $$tmp >/dev/null; \
	excludes="--exclude=README.md --exclude=SHA256SUMS"; \
	for d in $(GO_VECTOR_DIRS) $(FOREIGN_VECTOR_DIRS); do excludes="$$excludes --exclude=$$d"; done; \
	if diff -r -q testdata/vectors $$tmp $$excludes; then \
		echo "reference-generated vectors match"; rm -rf $$tmp; \
	else \
		echo "COMMITTED VECTORS DIFFER FROM THE REFERENCE — run 'make vectors'"; \
		rm -rf $$tmp; exit 1; \
	fi
	@tmp=$$(mktemp -d); cp -R testdata/vectors/. $$tmp/; \
	$(GO) run ./cmd/norn-genlog $$tmp >/dev/null; \
	ok=1; \
	for d in $(GO_VECTOR_DIRS); do \
		diff -r -q testdata/vectors/$$d $$tmp/$$d || ok=0; \
	done; \
	rm -rf $$tmp; \
	if [ $$ok -eq 1 ]; then \
		echo "Go-generated vectors match"; \
	else \
		echo "SERVED LOG OR PROOFS DIFFER — run 'make vectors-log'"; exit 1; \
	fi

# The Python reference's own unit tests.
ref-test:
	cd contrib/norn-ref && .venv/bin/python -m unittest discover -s tests

# The independent verifier (contrib/verify-py/PROVENANCE.md), run exactly as
# written: it was built for a sealed layout -- `vectors/` beside
# `work/verify-py/` -- and writes its outputs beside itself, so it runs on a
# copy of both in a temporary directory and the tree stays untouched. Plain
# python3, not the reference's virtualenv: it needs nothing but the standard
# library, and running it elsewhere would hide that.
verify-py:
	@tmp=$$(mktemp -d); mkdir -p $$tmp/work; \
	cp -R testdata/vectors $$tmp/vectors; cp -R contrib/verify-py $$tmp/work/verify-py; \
	(cd $$tmp && python3 -B work/verify-py/harness.py > harness.log 2>&1); \
	if ! grep -q ' checks; ' $$tmp/harness.log; then \
		echo "verify-py: the harness did not finish:"; tail -20 $$tmp/harness.log; rm -rf $$tmp; exit 1; fi; \
	grep -E ' FAIL$$' $$tmp/harness.log | grep -v ' checks; ' | sed 's/ FAIL$$//' | sort > $$tmp/failed; \
	grep -v '^#' contrib/verify-py.known-failures | grep -v '^$$' | sort > $$tmp/known; \
	if ! diff $$tmp/known $$tmp/failed > $$tmp/diff; then \
		echo "verify-py: failures differ from contrib/verify-py.known-failures"; \
		echo "  (< recorded but no longer failing, > failing but not recorded)"; \
		cat $$tmp/diff; tail -1 $$tmp/harness.log; rm -rf $$tmp; exit 1; fi; \
	tail -1 $$tmp/harness.log; n=$$(wc -l < $$tmp/known | tr -d ' '); \
	if [ $$n -ne 0 ]; then echo "  all $$n recorded in contrib/verify-py.known-failures (row 6.7-r owes a new cold run)"; fi; \
	rm -rf $$tmp

ci: fmt-check vet test verify-py

# The pinned `transparency-dev/witness` used by internal/interop. It is built
# outside this module on purpose: its own go.mod pulls Cloud Spanner, gRPC,
# OpenTelemetry and sqlite, and none of that belongs in a verifier's
# dependency graph. `go.work` is not used either -- the point is that Norn and
# the witness share no code at all.
WITNESS_VERSION = 55a5a0bf332a04f64296841ea857f86ec4494fc3

.PHONY: witness
witness:
	@mkdir -p build $(CURDIR)/build/witness-src
	@cd $(CURDIR)/build/witness-src && \
	  (test -f go.mod || printf 'module norn-witness-build\n\ngo 1.25\n' > go.mod) && \
	  $(GO) get github.com/transparency-dev/witness/cmd/omniwitness@$(WITNESS_VERSION) && \
	  $(GO) get github.com/transparency-dev/witness/cmd/generate_keys@$(WITNESS_VERSION) && \
	  $(GO) build -o $(CURDIR)/build/omniwitness github.com/transparency-dev/witness/cmd/omniwitness && \
	  $(GO) build -o $(CURDIR)/build/generate_keys github.com/transparency-dev/witness/cmd/generate_keys
	@echo "built build/omniwitness and build/generate_keys at $(WITNESS_VERSION)"

.PHONY: vectors-sums
# The temporary file is written *outside* the directory being hashed: a
# redirect creates it before `find` runs, so writing it in place lists it in
# its own output.
vectors-sums:
	@tmp=$$(mktemp); cd testdata/vectors && \
	  find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | \
	  xargs shasum -a 256 > $$tmp && mv $$tmp SHA256SUMS && chmod 644 SHA256SUMS
	@echo "wrote testdata/vectors/SHA256SUMS ($$(wc -l < testdata/vectors/SHA256SUMS | tr -d ' ') files)"
