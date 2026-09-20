GO      ?= go
PKGS    := ./...

.PHONY: all test vet fmt fmt-check lint ci vectors vectors-log vectors-check ref-test tidy

all: ci

test:
	$(GO) test -race -count=1 $(PKGS)

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

# The suite has two provenances (SPEC 12): the entry, state and trust vectors
# come from the Python reference, and the served log and proof bundles come
# from the Go implementation, because producing a tiled log needs one. Each
# half is checked against its own generator; neither is checked against itself
# alone, since upstream libraries validate both.
GO_VECTOR_DIRS := served proofs fork

# Vectors neither of Norn's implementations produces. `anchors` holds a `.ots`
# written by python-opentimestamps, and regenerating it would defeat the point
# of having it: it is in the suite because somebody else's code wrote the bytes.
FOREIGN_VECTOR_DIRS := anchors

# Regenerate the served log and proof bundles from the Go implementation.
vectors-log:
	$(GO) run ./cmd/norn-genlog testdata/vectors

# The committed vectors ARE the contract. Prove each half is exactly what its
# generator produces. Without this a stale file can survive indefinitely --
# seven once did.
vectors-check:
	@tmp=$$(mktemp -d); \
	PYTHONPATH=contrib/norn-ref $(PY) contrib/norn-ref/gen_vectors.py $$tmp >/dev/null; \
	excludes="--exclude=README.md"; \
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

ci: fmt-check vet test

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
