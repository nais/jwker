KUBEBUILDER_VERSION := 3.9.0
K8S_VERSION         := 1.26.1
arch                := amd64
os                  := $(shell uname -s | tr '[:upper:]' '[:lower:]')

all: jwker gettoken generateJWK

# Run tests
fmt:
	go run mvdan.cc/gofumpt -w ./
vet:
	go vet ./...
test: fmt vet
	go test ./... -coverprofile cover.out

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

static:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

deadcode:
	go run golang.org/x/tools/cmd/deadcode@latest -filter "internal/test/client.go" -filter "internal/test/test.go" -test ./...

helm-lint:
	helm lint --strict ./charts

check: static deadcode vuln helm-lint

integration_test:
	go test ./pkg/tokendings/gettoken_test.go -tags=integration -v -count=1

# Build manager binary
jwker:
	go build -o bin/jwker cmd/jwker/main.go

gettoken:
	go build -o bin/gettoken cmd/gettoken/main.go

generateJWK:
	go build -o bin/generateJWK cmd/generateJWK/main.go

kubebuilder:
	test -d /usr/local/kubebuilder || (sudo mkdir -p /usr/local/kubebuilder && sudo chown "${USER}" /usr/local/kubebuilder)
	wget -qO - "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-${K8S_VERSION}-$(os)-$(arch).tar.gz" | tar -xz -C /usr/local
	wget -qO /usr/local/kubebuilder/bin/kubebuilder https://github.com/kubernetes-sigs/kubebuilder/releases/download/v${KUBEBUILDER_VERSION}/kubebuilder_$(os)_$(arch)
	chmod +x /usr/local/kubebuilder/bin/*
