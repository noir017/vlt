.PHONY: build test fmt vet check clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/vlt ./cmd/vlt

test:
	go test ./... -count=1

fmt:
	gofmt -w .

vet:
	go vet ./...

check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi
	go vet ./...
	go test ./... -count=1

clean:
	rm -rf bin dist
