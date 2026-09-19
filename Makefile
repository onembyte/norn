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
GO_VECTOR_DIRS := served proofs

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
	for d in $(GO_VECTOR_DIRS); do excludes="$$excludes --exclude=$$d"; done; \
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
