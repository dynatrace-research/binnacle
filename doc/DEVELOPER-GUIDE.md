# Development Guide

## Prerequisites
- locally installed `kubectl` which has the context for the target Kubernetes cluster configured
- access to a `TypeDB` database with at least version `2.4` 
  - it can be installed locally - the download installation instructions can be found on the [homepage](https://vaticle.com/download#typedb)



### (Optional) Setup local cluster:

Setup with kubeProxy replacemend as documented by [Cilium](https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/#kubeproxy-free)
```shell
# get name of control-plane node
export KIND_CLUSTER=`kubectl get nodes | grep control-plane | cut -d' ' -f1`

helm upgrade --install cilium cilium/cilium --version 1.14.1 \v
    --namespace kube-system \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost=${KIND_CLUSTER} \
    --set k8sServicePort=6443
```

## Installation

Binnacle is packaged using [poetry](https://python-poetry.org/). To install it locally:
1) clone the repository
2) install the dependencies with `poetry install`  

_Note: this project requires Poetry v1.2+_

## Run

1) start the TypeDB database by executing `typedb server`.
2) To load a specific kubernetes cluster/namespace into the knowledge base execute  
`poetry run binnacle populate --db-host <TypeDB IP>:<TypeDB Port> --db-name <name of database> --ns <target namespace>`  
    if the database uses the default host and port, these arguments can be skipped


## API Usage

For details on the API endpoints please refer to the OpenAPI documentation at `http;//<ip:8000>/docs`

### Register a cluster with Binnacle

To register a cluster in the kubeconfig file execute
```
curl --request POST \
  --url 'http://$BINNACLE/clusters'  \
  --header 'Content-Type: application/json' \
  --data '{
    "name": "my-project",
    "cluster": {
        "name": "my-server,
        "server": "<API-ENDPOINT>",
        "ca_data": "<SERVER_CA_DATA>"
    },
    "user": {
        "name": "my-user",
        "token": "<TOKEN>", // or
        "cert_data": "<CERT_DATA>", 
        "key_data": "<KEY_DATA>"
    }
}'
```
The request to register a new cluster consists of 3 parts:
- the name of the cluster: `name`
- information about the `cluster`, with sub-fields: 
    - `server`  is the URL to the API-server of the cluster
    - `ca_data` or `certificate-authority-data`: the CA certificate to authenticate the cluster
- the user to `user` when interacting with the cluster:
    - `name` of the user entry (not relevant for the authentication)
    - one way to authorize (see below)


#### Authentication
There are multiple ways to authenticate against a Kubernetes cluster, which can be defined when registering a cluster by the corresponding fields in the HTTP POST request.


| Method         | Used for     | Field in request |
|--------------|-----------|------------|
| Certificate   | Developers, Admins   | `cert_data` or `client-certificate-data`  <br> `key_data` or `client-key-data`   | 
| Bearer Token  | Temporary Access, EKS  | `token` |
| Basic Auth    | _(avoid if possible)_  | `username` <br> `password` |

_Note: Bearer **token** and **basic auth** are **mutually exclusive**!_


### Add EKS Cluster

Currently, Binnacle has no native support for AWS EKS. To onboard a new EKS cluster you need to obtain 
- cluster information (see image below):
    1) **API server endpoint**: corresponds to the `server` field in the registration request
    2) **Cluster ARN**: corresponds to the optional `name` field of the cluster and user in the registration request
    3) **CA certifcate**: corresponds to the `ca_data` or `certificate-authority-data` field in the reqistration request
- and a token for authentication on that cluster

To obtain this you can either navigate to the web-ui of the target EKS cluster and copy the information for the first 3 times:
![](EKS-info.png)

Alternatively, the cluster information can be obtained using `aws-cli` to get a JSON object with all the required fields:
>  `aws eks describe-cluster --name $CLUSTER_NAME --region $REGION | jq -r '.cluster | {"arn":.arn, "endpoint":.endpoint, "ca-data":.certificateAuthority.data}'`

To get the **token** use `aws-cli`: 
> `aws eks get-token --cluster-name $CLUSTER_NAME --region $REGION`
This token can specified with the corresponding `token` field for a user in the registration request 



## Test Setup

### Install Load Balancer
- [LoadBalancer on KinD](https://kind.sigs.k8s.io/docs/user/loadbalancer/)  uses [Metallb](https://metallb.universe.tf/)

1) deploy Metallb custom resources in cluster (and dedicated namespace)
2) Get IP range assigned to docker nodes  
    `docker network inspect -f '{{.IPAM.Config}}' kind`
3) Create `IpAddressPool` and `L2Advertisment` resources for Metallb in K8s cluster
    ```yaml apiVersion: metallb.io/v1beta1
    kind: IPAddressPool
    metadata:
    name: example
    namespace: metallb-system
    spec:
    addresses:
    - <DOCKER_IP_HOST_NET>.200-<DOCKER_IP_HOST_NET>.250
    ---
    apiVersion: metallb.io/v1beta1
    kind: L2Advertisement
    metadata:
    name: empty
    namespace: metallb-system
    ```
4) deploy loadbalancer service and pods



### Setup Cilium on Kind Cluster

[Cilium setup for Kind](https://docs.cilium.io/en/v1.9/gettingstarted/kind/#getting-started-using-kind)
- ensure to enable:
    - hostPort: [enable PortMap](https://docs.cilium.io/en/v1.7/gettingstarted/cni-chaining-portmap/#portmap-hostport)
    - nodePort
    - [Hubble Metrics](https://docs.cilium.io/en/v1.7/gettingstarted/cni-chaining-portmap/#portmap-hostport) to observed network policy decisions 


```shell
helm install cilium cilium/cilium --version 1.13.4 \
   --namespace kube-system \
   --set nodeinit.enabled=true \
   --set kubeProxyReplacement=partial \
   --set hostServices.enabled=false \
   --set externalIPs.enabled=true \
   --set nodePort.enabled=true \
   --set hostPort.enabled=true \
   --set bpf.masquerade=false \
   --set image.pullPolicy=IfNotPresent \
   --set ipam.mode=kubernetes \
   --set hubble.enabled=true \
   --set prometheus.enabled=true \
   --set operator.prometheus.enabled=true \
   --set hubble.enabled=true \
   --set hubble.metrics.enableOpenMetrics=true \
   --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,httpV2:exemplars=true;labelsContext=source_ip\,source_namespace\,source_workload\,destination_ip\,destination_namespace\,destination_workload\,traffic_direction}"
```

## 🏛️ Architecture  


Either entrypoint interacts with the `Service` component, which manages any interaction with Binnacle.

The domain knowledge is modeled in the `Domain Model` component, which includes the supported entities and any rules for the inference.

The information is persisted in a dedicated repository _(currently only TypeDB is supported!)_, which is abstracted in the `Adapters` component.

![](docs/diagrams/container_view.png)