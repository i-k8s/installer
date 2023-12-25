#!/usr/bin/env python3
import subprocess

master_ips = []
worker_ips = []
master_count = 0
worker_count = 1
has_internet = False
docker_registry = "dr.io"
docker_registry_ip = "dr.io"
vip = ""
lbpool = ""
join_command = ""
interface = ""
ip = ""
is_master = False
is_first_master = False
ha_proxy_installed = False
docker_registry_with_slash = ""
single_node = False
wildcard_domain = "k8s.amprajin.in"
use_ceph = False
ceph_mon_ips = []
ceph_user = ""
ceph_key = ""
nfs_server = ""
nfs_path = ""
use_public_ip_for_dashboard = False

# Function to execute shell commands
def execute_command(command):
    """Executes a shell command and returns the output and error."""
    print("Executing command: {}".format(command))
    print("Please wait... \n \n______________________________\n")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode(), error.decode()

def get_lan_interface_name():
  """Returns the name of the LAN interface on Ubuntu."""

  output,error = execute_command("ip -o link show | awk -F': ' '{print $2}'")
  for line,i in output.splitlines():
    print(i)
    print(line)
    if 'e' in line and 'lo' not in line:
      return line
def get_lan_interface_ip():
    """Returns the IP address of the LAN interface on Ubuntu."""
    
    output,error = execute_command(f"ip addr show {interface} | grep -oP 'inet\s+\K[\d.]+'")
    lines = output.splitlines()
    if len(lines) > 0:
        if len(lines) > 1:
            print("Multiple IP addresses found for interface {}".format(interface))
            print("Please enter the IP address to be used: ")
            for i in range(len(lines)):
                print("{}: {}".format(i+1, lines[i]))
            input = input()
            if input.isdigit() and int(input) <= len(lines):
                return lines[int(input()) - 1]
            else:
                print("Invalid input")
                exit(1)
        return lines[0]
    else:
        print("Error getting IP address for interface {}".format(interface))
        exit(1)
def generate_haproxy_config(num_masters):
    config = f"""cat >> /etc/haproxy/haproxy.cfg <<EOF

frontend kubernetes-frontend
  bind *:8443
  mode tcp
  option tcplog
  default_backend kubernetes-backend

backend kubernetes-backend
  option httpchk GET /healthz
  http-check expect status 200
  mode tcp
  option ssl-hello-chk
  balance roundrobin
"""
    for i in range(1, num_masters + 1):
        config += f"    server master{i} master{i}.in:6443 check fall 3 rise 2\n"

    config += "EOF"
    return config
# Function to collect node information
def collect_node_info():
    # Collect node information here based on the provided data
    global master_count
    global worker_count
    global master_ips
    global worker_ips
    global interface
    global ip
    global is_master
    global is_first_master
    global ha_proxy_installed
    global docker_registry_with_slash
    global single_node
    global has_internet
    global docker_registry
    global vip
    global lbpool
    global wildcard_domain
    global use_ceph
    global ceph_mon_ips
    global ceph_user
    global ceph_key
    global nfs_server
    global nfs_path

    master_count = int(input("Enter the number of master nodes (0 if singlenode setup): "))
    
    for i in range(master_count):
        master_ips.append(input("Enter the IP address of master node {}: ".format(i+1)))
    print("master_ips: {}".format(master_ips))

    if master_count == 0:
        worker_count = 1
    else:
        worker_count = int(input("Enter the number of worker nodes: "))
    for i in range(worker_count):
        worker_ips.append(input("Enter the IP address of worker node {}: ".format(i+1)))
    print("worker_ips: {}".format(worker_ips))
    global interface 
    while interface == "":
        interface = get_lan_interface_name()
        print("LAN interface is {} is this correct (y/n)".format(interface))
        if input() == "n":
            interface = input("Enter the LAN interface name: ")
    while ip == "":
        ip = get_lan_interface_ip()
        print("LAN interface IP is {} is this correct (y/n)".format(ip))
        if input() == "n":
            ip = input("Enter the LAN interface IP: ")
        ## check ip is in master_ips or worker_ips
        if not (ip in master_ips or ip in worker_ips):
            print("IP not in master_ips or worker_ips")
            ip = ""
    if len(master_ips) == 0 and len(worker_ips) == 1:
        if ip == worker_ips[0]:
            is_master = True
            is_first_master = True
            single_node = True
        
    if ip in master_ips:
        is_master = True
        if ip == master_ips[0]:
            is_first_master = True
        

    ip = get_lan_interface_ip()
    while True:
        has_internet = input("Does the cluster have permenant internet access? (y/n): ")
        if has_internet == "y" or has_internet == "n":
            break
    has_internet = has_internet == "y"
    if not has_internet:
        docker_registry = input("Enter the docker registry to be used: ")
        docker_registry_with_slash = docker_registry.endswith("/") and docker_registry or docker_registry + "/"

    vip = input("Enter the VIP to be used: ")
    lbpool = input("Enter the load balancer pool to be used: ")
    wildcard_domain = input("Enter the wildcard domain to be used: ")
    use_ceph = input("Do you want to use Ceph for storage? (y/n): ")
    use_ceph = use_ceph == "y"
    if use_ceph:
        ceph_mon_ips = input("Enter the Ceph monitor IPs (comma separated): ").split(",")
        ceph_user = input("Enter the Ceph user: ")
        ceph_key = input("Enter the Ceph key: ")
    else:
        nfs_server = input("Enter the NFS server IP: ")
        nfs_path = input("Enter the NFS path: ")

def print_node_info():
    # Print collected node information
    print("master_count: {}".format(master_count))
    print("worker_count: {}".format(worker_count))
    print("master_ips: {}".format(master_ips))
    print("worker_ips: {}".format(worker_ips))
    print("interface: {}".format(interface))
    print("ip: {}".format(ip))
    print("is_master: {}".format(is_master))
    print("is_first_master: {}".format(is_first_master))
    print("ha_proxy_installed: {}".format(ha_proxy_installed))
    print("docker_registry_with_slash: {}".format(docker_registry_with_slash))
    print("single_node: {}".format(single_node))
    print("has_internet: {}".format(has_internet))
    print("docker_registry: {}".format(docker_registry))
    print("vip: {}".format(vip))
    print("lbpool: {}".format(lbpool))
    print("wildcard_domain: {}".format(wildcard_domain))
    print("use_ceph: {}".format(use_ceph))
    print("ceph_mon_ips: {}".format(ceph_mon_ips))
    print("ceph_user: {}".format(ceph_user))
    print("ceph_key: {}".format(ceph_key))
    print("nfs_server: {}".format(nfs_server))
    print("nfs_path: {}".format(nfs_path))

# Function to add entries to /etc/hosts
def update_hosts_file():
    # Add entries to /etc/hosts based on collected node information
    # Add entries for master nodes
    # Add entries for worker nodes
    # Add entries for load balancer
    # Add entries for registry
    # Add entries for VIP as master.in
    command = "echo \"{} master.in\" >> /etc/hosts".format(vip)
    execute_command(command)
    for i in range(master_count):
        command = "echo \"{} master{}.in\" >> /etc/hosts".format(master_ips[i], i+1)
        execute_command(command)
    for i in range(worker_count):
        command = "echo \"{} worker{}.in\" >> /etc/hosts".format(worker_ips[i], i+1)
        execute_command(command)
    command = "echo \"{} {}\" >> /etc/hosts".format(docker_registry_ip,docker_registry)
    execute_command(command)




# Function to install containerd
def install_containerd():
    # Check if containerd is installed
    output, error = execute_command("which containerd")
    if output == "":
        # Install containerd
        # Add containerd configuration
        # Restart containerd
        # Enable containerd
        # Check containerd status
        execute_command("curl -fsSLo containerd-config.toml \
  https://gist.githubusercontent.com/oradwell/31ef858de3ca43addef68ff971f459c2/raw/5099df007eb717a11825c3890a0517892fa12dbf/containerd-config.toml")
        execute_command("sudo mkdir -p /etc/containerd")
        execute_command("sudo mv containerd-config.toml /etc/containerd/config.toml")
        execute_command("curl -fsSLo containerd-1.6.14-linux-amd64.tar.gz \
  https://github.com/containerd/containerd/releases/download/v1.6.14/containerd-1.6.14-linux-amd64.tar.gz")
        execute_command("sudo tar Cxzvf /usr/local containerd-1.6.14-linux-amd64.tar.gz")
        execute_command("sudo curl -fsSLo /etc/systemd/system/containerd.service \
  https://raw.githubusercontent.com/containerd/containerd/main/containerd.service")
        execute_command("sudo systemctl daemon-reload")
        execute_command("sudo systemctl enable --now containerd")
        execute_command("sudo systemctl restart containerd")
        execute_command("sudo systemctl status containerd")

        execute_command("curl -fsSLo runc.amd64 \
  https://github.com/opencontainers/runc/releases/download/v1.1.3/runc.amd64")
        execute_command("sudo install -m 755 runc.amd64 /usr/local/sbin/runc")
    else:
        print("Containerd already installed, Please check if it is configured correctly")
        print(" warning !! recommented to unistall all dependencies before installing this")

    execute_command("""cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF""")
    execute_command("sudo modprobe -a overlay br_netfilter")
    execute_command("sudo modprobe br_netfilter")


    # If not installed, follow the provided steps to install containerd



# Function to install Kubernetes components
def install_kubernetes():
    # Add Kubernetes GPG key
    execute_command("curl -fsSL https://dl.k8s.io/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-archive-keyring.gpg")
    # Add Kubernetes apt repository
    execute_command("echo \"deb [signed-by=/etc/apt/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main\" | sudo tee /etc/apt/sources.list.d/kubernetes.list")
    # Install kubeadm, kubelet & kubectl
    execute_command("sudo apt-get update")
    execute_command("sudo apt-get install -y  kubelet=1.25.8-00 kubeadm=1.25.8-00 kubectl=1.25.8-00")
    execute_command("sudo apt-mark hold kubelet kubeadm kubectl")
    # Disable swap
    execute_command("sudo swapoff -a")
    execute_command("sudo sed -i -e '/swap/d' /etc/fstab")
    # firewall allow ports 22,80,443,8443,6443,2379,2380,10250,10257,10259,30000-32767
    execute_command("sudo ufw allow 22,80,443,8443,6443,2379,2380,10250,10257,10259/tcp")
    execute_command("sudo ufw allow 30000:32767/tcp")
    # Configure kubectl

# Function to install and configure Keepalived & HAProxy
def install_keepalived_haproxy():
    # Install and configure Keepalived & HAProxy on multiple master nodes if needed
    if is_master and master_count > 1:
        ha_proxy_installed = True
        execute_command("sudo apt update && sudo apt install -y keepalived haproxy")
        execute_command("""cat >> /etc/keepalived/check_apiserver.sh <<EOF
#!/bin/sh

errorExit() {
  echo "*** $@" 1>&2
  exit 1
}

curl --silent --max-time 2 --insecure https://localhost:6443/ -o /dev/null || errorExit "Error GET https://localhost:6443/"
if ip addr | grep -q {vip}; then
  curl --silent --max-time 2 --insecure https://master.in:8443/ -o /dev/null || errorExit "Error GET https://master.in:8443/"
fi
EOF""".format(vip=vip))
        execute_command("sudo chmod +x /etc/keepalived/check_apiserver.sh")
        
        execute_command("""cat >> /etc/keepalived/keepalived.conf <<EOF
vrrp_script check_apiserver {
  script "/etc/keepalived/check_apiserver.sh"
  interval 3
  timeout 10
  fall 5
  rise 2
  weight -2
}

vrrp_instance VI_1 {
    state BACKUP
    interface {interface}
    virtual_router_id 1
    priority 100
    advert_int 5
    authentication {
        auth_type PASS
        auth_pass mysecret
    }
    virtual_ipaddress {
        {vip}
    }
    track_script {
        check_apiserver
    }
}
EOF""".format(vip=vip,interface=interface))
        
        execute_command("systemctl enable --now keepalived")
        execute_command("sudo systemctl status keepalived")
        execute_command(generate_haproxy_config(master_count))
        execute_command("systemctl enable haproxy && systemctl restart haproxy")
        execute_command("sudo systemctl status haproxy")

# Function to create Kubernetes cluster using kubeadm
def create_kubernetes_cluster():
    # pull images
    output=None
    error=None
    if(has_internet):
        output, error = execute_command("sudo kubeadm config images pull --kubernetes-version=v1.25.8")
    else:
        
        output, error = execute_command("sudo kubeadm config images pull --image-repository {}registry.k8s.io --kubernetes-version=v1.25.8".format(docker_registry_with_slash))
    if error != None:
        print("Error pulling images")
        print(error)
        exit(1)
    # Initialize the cluster using kubeadm
    if is_master:
        if is_first_master:
            command  = "sudo kubeadm init --pod-network-cidr=192.168.0.0/16 --kubernetes-version=v1.25.8"
            if has_internet:
                command = command + " --image-repository {}registry.k8s.io".format(docker_registry_with_slash)
            if ha_proxy_installed:
                command = command + " --control-plane-endpoint \"master.in:8443\""
            output, error = execute_command(command)
            if error != None:
                print("Error initializing master")
                print(error)
                exit(1)
            if single_node:
                execute_command("kubectl taint nodes --all node-role.kubernetes.io/master-")
                execute_command("kubectl taint nodes --all node-role.kubernetes.io/control-plane-")
        else:
            join_command = input("Enter the join command: ")
            output, error = execute_command(join_command)
            if error != None:
                print("Error joining master")
                print(error)
                exit(1)
    else:
        join_command = input("Enter the join command: ")
        output, error = execute_command(join_command)
        if error != None:
            print("Error joining worker")
            print(error)
            exit(1)
                
    
    # Configure kubectl
    # delete old config
    execute_command("rm -rf $HOME/.kube")
    execute_command("mkdir -p $HOME/.kube")
    execute_command("sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config")
    execute_command("sudo chown $(id -u):$(id -g) $HOME/.kube/config")

# Function to install Helm
def install_helm():
    # Install Helm and configure as required
    execute_command("curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null")
    execute_command("""sudo apt-get install apt-transport-https --yes""")
    execute_command("""echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list""")
    execute_command("""sudo apt-get update""")
    execute_command("""sudo apt-get install  -y helm""")

def deploy_calico():
    execute_command("""helm repo add projectcalico https://docs.tigera.io/calico/charts""")
    execute_command("""helm repo update""")
    execute_command("""helm install calico projectcalico/tigera-operator --version v3.25.2 --namespace tigera-operator --create-namespace""")
    ## sleep for 2 minutes
    execute_command("""sleep 120""")
    # wait until calico is deployed
    execute_command("""kubectl wait --for=condition=Available --timeout=600s deployment/calico-kube-controllers -n tigera-operator""")
def check_status():
    # Check if all the pods are running
    execute_command("kubectl get pods --all-namespaces")
    # Check if all the nodes are ready
    execute_command("kubectl get nodes")
    # Check if the cluster is ready
    execute_command("kubectl get cs")

def install_k8s():
    output, error = execute_command(" helm install k8s-dependencies ./k8s-dependencies -n k8s --create-namespace --set imageRegistry={} --set ipPool={}".format(docker_registry,lbpool))
    if error != None:
        print("Error installing k8s-dependencies")
        print(error)
        exit(1)
    execute_command("sleep 600")
    use_public_ip_for_dashboard = input("Do you want to use public IP for dashboard? (y/n): ")
    use_public_ip_for_dashboard = use_public_ip_for_dashboard == "y"
    

    command = """helm install k8s ./k8s -n k8s --create-namespace \
                                --set nfs-server-provisioner.storageClass.parameters.server={} \
                                --set nfs-server-provisioner.storageClass.parameters.path={} \
                                --set kubernetes-dashboard.app.ingress.hosts[0]={}""".format(nfs_server,nfs_path,wildcard_domain.replace("*","k8sdb"))
    if use_public_ip_for_dashboard:
        command = command + " --set kubernetes-dashboard.app.ingress.ingressClassName=publicIngress --set kubernetes-dashboard.app.ingress.issuer=cluster-issuer-public"
    output, error =execute_command(command)
    if error != None:
        print("Error installing k8s")
        print(error)
        exit(1)
    

# Main function to orchestrate the setup process
def main():
    proceed = False 
    while not proceed:
        collect_node_info()
        print_node_info()
        i = input("\n\n Are you sure you want to proceed with the installation? (y/n/c)")
        if i == "y":
            proceed = True
        elif i == "c":
            print("Exiting...")
            exit(1) 

    update_hosts_file()
    install_containerd()
    install_kubernetes()
    install_keepalived_haproxy()
    create_kubernetes_cluster()
    install_helm()
    deploy_calico()
    check_status()

if __name__ == "__main__":
    main()
