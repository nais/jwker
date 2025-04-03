#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= release-0.19
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= 1.31.0
## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

ENVTEST ?= $(LOCALBIN)/setup-envtest

install-crd:
	kubectl apply -f https://raw.githubusercontent.com/nais/liberator/main/config/crd/bases/nais.io_jwkers.yaml

sample:
	kubectl apply -f ./doc/jwker-sample.yaml

fmt:
	go tool gofumpt -w ./

vet:
	go vet ./...

test: fmt vet
	go test ./... -coverprofile cover.out

vuln:
	go tool govulncheck ./...

static:
	go tool staticcheck ./...

deadcode:
	go tool deadcode -test ./...

helm-lint:
	helm lint --strict ./charts

check: static deadcode vuln

# the JWK is a randomly generated key for testing purposes only
local: fmt
	CLUSTER_NAME="local" \
    JWKER_PRIVATE_JWK='{"p":"u_vEgDmK2pi85XqDTBS7DAeCLHPu-ImWBia9ajKhFF00-zKibzPl8Fib-EmQamZIAhla124d1QzNPS6Gt8WQvx2YocE5CTIAecFqY5bJ_SdNyIlnBjIrfzTL80N5rQRWeObGxllYSVNCWF-Zynwdyg0CZ6EqKG1T01QMEwkEAyk","kty":"RSA","q":"tAiZOAJkbjFuntA-fAdweQg5RR1qZLklD6I_qBhYibwgvvzJ4Vqj7OOOEaMAvyYnzX7RxFPgLWt4GSqvEq8AVnmAyqut5RYv72QSI61qsEGftIrrC6JYgedrwY77QTikEK1WpdULXgdXEAfn3vFCyRy7I4p1Rgxk7ALufzNw6Rc","d":"axB4wjyUx0G9I-OZrqcGE5xe51m9I_n9kBMVaqnBUjODkrUnuBm5RRRgzNxRiCXcMBTk1xT6xTpTgzRWyueE8zjbj_qT4CFIxjBwWhPJt-EUmNZOdLSgRnDMyENv0XLclQITeDKPq6I7LCcS-WPeANfnpSMzpZRBYR4Dza-3j1aFfCsqUB2YUt4AGhCY3RaFmGYHBbqTLYlsBgRXoEVBstVVwrCfAXAr1VwHVpUNLBqYxqc91EL-4bOBx2B5OGLLEKOFMKjAwZ4GrLOfWO5Hvg2XNtBJ2zyybk35p5SaD7x5pNtL2YXaD7VlLfSlDKPjKihHGVg16sd_YFTCQMF4wQ","e":"AQAB","use":"sig","kid":"BSt_Sm3KNncQlynd9V1PylFRi3H6DXjU3QKoDAUaB0E","qi":"PGJcOcXcoFmUj0LUzRvtMGqUDmzoSs88iJtdlDogXVzdOTJA8YYQOH9LiamD9m51jfinNumiALhCKPsFwEKG21jEoy3T0LlWm7gvg3sOeyL2HblP-YHPmGkgauxFVfa2NN6JdpTTd_z8nM_Gu1zHEeAB93xy1y62uqZE3pgK6po","dp":"ESToCe21jTQq3h7rRJALcxBoPdeg7sfVh-AWnE3bxPivMU2v5MZt7RqXtvA2nI2ReaeIUmd3jwuo2DCbFr2M8vEnD3GI2x7VTkVmh4ikCVOBU428eKMwtlxBUYFQ4oenv0UE0egqFh3iyh6F7yKcsOW412yqZJ976qUaqM3EsOk","alg":"RS256","dq":"bqumfI7D7BVJGimLb7UnB8_tXLZTc-14gd7MYOnua2URgDZnZ7fPc00DRYY9bEPpTeK60oR5F5Kr9lSN4N9hRsdUS8IzmNMFzpRmrjXpksYUheiryrAW1mxLimX5wEMwX-weirynSzsZ4wnpGNyYoIaf554yr0fpNkgrElit_Ss","n":"hDNWiuW8w0cKAG2Ssjujcch8kvpUiAMYJUcBeYXuu4N4vzKx1Jj2VBFkY06SsAb3Z5b9_k-cunkWRYgVc0Sf8_NWfrVCA8SLBgGJUjBxp2ttHJZKLVqHJMIuYr468dUfCr1iHcdumTwhfClv9cTiD4Bl2m5Id_bF23S6RflF0TD6ziLoMXo3SwosX6yN2mCqdy4PoocS8bjV2Fj93UxRN2h7qA4TfBwSx91kBCAzOFFZ84IAgP9u5nwH29q_5_piJHjlAhD6LY8Lc_tXk5rMh_75Z-83EEJlhqPm20jalIYNaigxCFUL_oK-I8IJvpsNH-ECqQs37dWU6dakAyyZrw"}' \
    JWKER_CLIENT_ID="jwker" \
    TOKENDINGS_URL="http://localhost:8080" \
    go run cmd/jwker/main.go

##@ Dependencies
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef
