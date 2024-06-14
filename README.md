<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# ACME webhook for desec.io DNS API

This solver can be used with [desec.io](https://desec.io) DNS API. The documentation
of the API can be found [here](https://desec.readthedocs.io/en/latest/)

## Requirements
- [go](https://golang.org) => 1.19.0
- [helm](https://helm.sh/) >= v3.0.0
- [kuberentes](https://kubernetes.io/) => 1.25.0
- [cert-manager](https://cert-managaer.io/) => 1.11.0

## Installation

### Using helm from local checkout
```bash
helm install desec-webhook -n cert-manager deploy
```
### Using public helm chart

```bash
helm repo add cert-manager-desec-webhook https://pr0ton11.github.io/cert-manager-desec-webhook/
helm install cert-manager-desec-webhook/desec-webhook -n cert-manager deploy

```

## Uninstallation

## Creating an issuer

Create a secret containing the credentials
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: desec-io-secret
  namespace: cert-manager
type: Opaque
data:
  token: your-key-base64-encoded
```

Create a 'ClusterIssuer' or 'Issuer' resource as the following:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: mail@example.com

    privateKeySecretRef:
      name: letsencrypt-staging

    solvers:
      - dns01:
          webhook:
            config:
              apiKeySecretRef:
                key: token
                name: desec-io-secret
            groupName: acme.example.com
            solverName: desec
```

## Create a manual certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-cert
  namespace: cert-manager
spec:
  commonName: example.com
  dnsNames:
    - example.com
  issuerRef:
    name: letsencrypt-staging
    kind: ClusterIssuer
  secretName: example-cert
```

## Using cert-manager with traefik ingress
```yaml

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bitwarden
  namespace: utils
  labels:
    app: bitwarden
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-staging
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/rewrite-target: /$1
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: 'true'
spec:
  tls:
    - hosts:
        - bitwarden.acme.example.com
      secretName: bitwarden-crt
  rules:
    - host: bitwarden.acme.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: bitwarden
                port:
                  number: 80

```

### Creating your own repository

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

Provide a secret.yaml in testdata/desec
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: desec-token
data:
  token: your-key-base64-encoded
type: Opaque
```

Define a **TEST_ZONE_NAME** matching to your authenticaton creditials.

```bash
$ TEST_ZONE_NAME=example.com. make test
```
