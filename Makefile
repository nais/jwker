KUBEBUILDER_VERSION := 3.2.0
K8S_VERSION         := 1.22.1
arch                := amd64
os                  := $(shell uname -s | tr '[:upper:]' '[:lower:]')

all: jwker gettoken generateJWK

# Run tests
test:
	go test ./... -coverprofile cover.out

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
	curl -L "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-${K8S_VERSION}-$(os)-$(arch).tar.gz" | tar -xz -C /usr/local
	curl -L -o /usr/local/kubebuilder/bin/kubebuilder https://github.com/kubernetes-sigs/kubebuilder/releases/download/v${KUBEBUILDER_VERSION}/kubebuilder_$(os)_$(arch)
	chmod +x /usr/local/kubebuilder/bin/*
