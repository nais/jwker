# Using tokens to communicate securely from app to app on behalf of a user

In order for an application to communicate with another application, both sides of the communication need to approve the other.
`application-1` needs to express that it intends to communicate with `application-2` and `application-2` needs to express that it intends to receive traffic from `application-1`.

When deploying an application to a nais cluster, these conditions can be expressed in the application manifest using `spec.accessPolicy`

```
apiVersion: "nais.io/v1alpha1"
kind: "Application"
metadata:
  name: application-2
...
spec:
  ...
  accessPolicy:
    inbound:
      rules:
        - application: application-1
```

```
apiVersion: "nais.io/v1alpha1"
kind: "Application"
metadata:
  name: application-1
...
spec:
  ...
  accessPolicy:
    outbound:
      rules:
        - application: application-2
```

Once an application manifest containing an `applicationPolicy` is deployed to a cluster, the `applicationPolicy` will be registered with `token-dings` and a private key will be injected in to the application's container.

`application-1` use its private key to sign the request for a token for `application-2` from `token-dings`.

Given that both `application-1` and `application-2` has registered their accessPolicies with `token-dings`, a token will be provided to `application-1`.

`application-1` sends this token along with its request to `application-2`, who in turn validates the token (using the public keys from `token-dings`) before handling the request.
