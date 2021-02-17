module github.com/nais/jwker

go 1.15

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-logr/logr v0.1.0
	github.com/go-logr/zapr v0.1.0
	github.com/google/uuid v1.1.1
	github.com/nais/liberator v0.0.0-20210217081730-10616faa752c
	github.com/prometheus/client_golang v1.0.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	go.uber.org/zap v1.15.0
	gopkg.in/square/go-jose.v2 v2.5.0
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v0.17.2
	sigs.k8s.io/controller-runtime v0.5.0
)
