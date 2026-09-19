GO      ?= go
PKGS    := ./...

.PHONY: all test vet fmt fmt-check lint ci vectors tidy

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

# Regenerate test vectors from the Python reference implementation (the oracle).
vectors:
	python3 contrib/norn-ref/gen_vectors.py testdata/vectors

ci: fmt-check vet test
