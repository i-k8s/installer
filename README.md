# Kubernetes Deployments
This will install kubernets using a single command
This repo keep all helem charts for kubernetes deployments to start and run the kubernetes cluster with dashboard and ingress controller

## Prerequisites

python3 is required to run the script

there will be no existing kubernetes cluster in the server

## Installation

Expecting git is alredy availble

otherwise isnatll git

```bash
sudo apt install git
```

```bash
git clone https://github.com/i-k8s/installer.git
cd installer
sudo chmod +x install.py

sudo ./install.py
```



## Helpful Commands

#### Commands to work with helm

Update dependencies

```bash
helm dependency update
```
 template the helm charts to see the output

```bash
helm template ./k8s-dependencies
helm template ./k8s
helm template ./service
helm template ./web-ext
```
template the helm charts to see the output with namespace into output-dir


```bash
helm template ./k8s-dependencies  --namespace k8s  --output-dir './output-dir'
helm template ./k8s  --namespace k8s --output-dir './output-dir'
```

dry run the helm charts to see the output with namespace (Kubernetes required)

```bash
helm install k8s-dependencies ./k8s-dependencies  --namespace k8s --create-namespace --dry-run
helm install k8s ./k8s  --namespace k8s --create-namespace --dry-run

```

Install the helm charts with namespace (Kubernetes required)

```bash
helm install k8s-dependencies ./k8s-dependencies  --namespace k8s --create-namespace --dry-run
helm install k8s ./k8s -n k8s --create-namespace
```


```bash
helm upgrade -i k8s-dependencies ./k8s-dependencies -n k8s --create-namespace
helm upgrade -i k8s ./k8s -n k8s --create-namespace
```

```bash
helm uninstall web-ext  -n inhouse
helm uninstall k8s  -n k8s
```

#### Commands to work with kubernetes

Create secret for docker registry if using private docker registry

```bash
kubectl create secret docker-registry regcred --docker-server=https://dr.io/ --docker-username=admin --docker-password=PassWord --docker-email=admin@dr.io -n namespace


```

get token for kubernetes dashboard

```bash
kubectl -n k8s create token guest-user --duration=720h
kubectl -n k8s create token admin-user --duration=720h
```

create secret for tls (SSL Certificate) for kubernetes ingress.

```bash
kubectl create secret tls tls-secret \
  --cert=certificate.crt \
  --key=private.key \
  --namespace k8s
```

```bash
kubectl create secret generic  generic-secret \
  --from-file=tls.crt=certificate.crt --from-file=tls.key=private.key --from-file=ca.crt=ca.crt \
  --namespace k8s
```

```bash
kubectl create secret tls tls-secret \
  --cert=certificate.crt \
  --key=private.key \
  --namespace inhouse
```


create helm token and update in gitlab

it will expire in 30 days so we need to update it in gitlab

```bash
kubectl create token helm --duration=720h
```

```
kubectl get secret kubernetes-dashboard-certs -o=jsonpath='{.data.ca.crt}' -n k8s | base64 --decode

```