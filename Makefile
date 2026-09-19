GO      ?= go
PKGS    := ./...

.PHONY: all test vet fmt fmt-check lint ci vectors vectors-check ref-test tidy

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

# The committed vectors ARE the contract. Prove they are exactly what the
# reference produces: regenerate into a scratch tree and diff. Without this,
# a stale file can survive in testdata/ indefinitely -- seven once did.
vectors-check:
	@tmp=$$(mktemp -d); \
	PYTHONPATH=contrib/norn-ref $(PY) contrib/norn-ref/gen_vectors.py $$tmp >/dev/null; \
	if diff -r -q testdata/vectors $$tmp --exclude=README.md; then \
		echo "vectors match the reference implementation"; rm -rf $$tmp; \
	else \
		echo "COMMITTED VECTORS DIFFER FROM THE REFERENCE — run 'make vectors'"; \
		rm -rf $$tmp; exit 1; \
	fi

# The Python reference's own unit tests.
ref-test:
	cd contrib/norn-ref && .venv/bin/python -m unittest discover -s tests

ci: fmt-check vet test
