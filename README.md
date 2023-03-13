# Jwker
An operator that updates [TokenDings](https://github.com/nais/token-exchange) based on the custom resource `nais.io/Jwker`.

The `Jwker` spec contains accesspolicies from `nais.io/Application` and a unique secret name for injecting a private JWKS to the application's container.

Applications use their private JWKS when they request `access_tokens` for communicating with other applications from TokenDings.

## Functionality
1. When an Application is generated or updated in a cluster, Naiserator will create a new `Jwker` resource with a new unique secret name.
1. The Jwker operator reads the `Jwker` and generates a jwks for the application. 
    1. If it is a new `Jwker`, a JWK is generated and its public key is added to a JWKS.
    1. If the `Jwker` is updated, a new JWK is generated and its public key is added to the JWKS along with the previous public JWK (fetched from storage). This ensures currently running applications remain functional during a rotating update.
1. The private JWKS is stored as a kubernetes secret using the name generated by Naiserator and mounted in to the application container.
1. The public JWKS is registered with TokenDings, along with the AccessPolicy from the `Jwker` spec.
    1. Each application is registered with a unique identifier in the form of `clustername:namespace:application` 

## Development
```
brew install kustomize
go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.2.5
```

The following environment variables are used to run jwker using token-dings mock as id-provider
```
AUTH_PROVIDER_WELL_KNOWN_URL=http://localhost:1111/aadmock/.well-known/openid-configuration
TOKENDINGS_CLIENT_ID=tokendings
JWKER_CLIENT_ID=jwker_client_id_1
TOKENDINGS_URL=http://localhost:8080
```

You will also need a jwk when fetching an access token from idprovider mock.
Generate a new jwk with the following command:
`go run cmd/generateJWK/main.go`
point to the file you've created with the following flag:
`--client-jwk-file=pkg/tokendings/testdata/jwk.json`


You also need a mock instance of token-dings locally in order to fetch tokens from a mock id-provider and register clients with a mock endpoint.

A mock of the token-dings endpoint is available here:
https://github.com/nais/token-exchange
Run `token-exchange/src/test/kotlin/io/nais/security/oauth2/mock/MockTokenExchangeApp.kt` from your prefered IDE in order to start a mock id-provider and token-dings

Deploy to your local cluster using
`make install && make deploy && make run`

## Verifying the Aivenator image and its contents

The image is signed "keylessly" (is that a word?) using [Sigstore cosign](https://github.com/sigstore/cosign).
To verify its authenticity run
```
cosign verify \
--certificate-identity "https://github.com/nais/jwker/.github/workflows/main.yml@refs/heads/master" \
--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
ghcr.io/nais/jwker@sha256:<shasum>
```

The images are also attested with SBOMs in the [CycloneDX](https://cyclonedx.org/) format.
You can verify these by running
```
cosign verify-attestation --type cyclonedx \
--certificate-identity "https://github.com/nais/jwker/.github/workflows/main.yml@refs/heads/master" \
--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
ghcr.io/nais/jwker@sha256:<shasum>
``` 

