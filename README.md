# Kubernetes Deployments

This repository houses all Helm charts necessary for Kubernetes deployments, facilitating the setup and management of a Kubernetes cluster with included dashboard and ingress controller using a single command.

## Prerequisites

Ensure that `python3` and `pip3` are available to run the script:

```bash
sudo apt update
sudo apt install python3 python3-pip
```

## Installation

If `git` isn't already available, install it:

```bash
sudo apt install git
```

Clone the repository and execute the installation script:

```bash
git clone https://github.com/i-k8s/installer.git
cd installer
sudo chmod +x install.py
sudo ./install.py
```

### Generate SSL Certificate

1. Navigate to the directory where you want to store your certificates, e.g., `/home/cert`.

   ```sh
   cd /home/cert
   ```

2. Generate a CA certificate private key:

   ```sh
   openssl genrsa -out tls.key 4096
   ```

3. Generate the CA certificate. If you have an existing certificate, you can use it, but ensure it's valid. Here's how to generate one that's valid for 10 years:

   ```sh
   openssl req -x509 -new -nodes -sha512 -days 3650 \
   -subj "/C=IN/ST=Kerala/L=Kerala/O=OpenSSL/OU=ADM/emailAddress=devops@openssl.in/CN=*.openssl.in" \
   -key tls.key \
   -out tls.crt
   ```

   Adjust the `-subj` flag to match your organization's details.

---

I've made some improvements in the formatting, corrected typos, and added clearer instructions. Is there anything specific you'd like to add or modify further?

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
helm uninstall k8s-dependencies  -n ik8s
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
  --namespace ik8s
```


create helm token and update in gitlab

it will expire in 30 days so we need to update it in gitlab

```bash
kubectl create token helm --duration=720h
```

```
kubectl get secret kubernetes-dashboard-certs -o=jsonpath='{.data.ca.crt}' -n k8s | base64 --decode

```

helm upgrade -i k8s ./k8s -n k8s --create-namespace --set nfs-server-provisioner.storageClass.parameters.server="192.168.175.183" --set nfs-server-provisioner.storageClass.parameters.path="/mnt/nfs_share" --set kubernetes-dashboard.app.ingress.hosts[0]="db.k8s1.ults.build"  --set kong-internal.enabled=false --set kong.enabled=true --set kong-internal.service.loadBalancerIP=192.168.175.126 --set kong.service.loadBalancerIP=192.168.175.125 --set kubernetes-dashboard.app.ingress.ingressClassName=pubing --set kubernetes-dashboard.app.ingress.issuer=cluster-issuer-public