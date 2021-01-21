
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
