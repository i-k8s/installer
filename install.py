#!/usr/bin/env python3
import subprocess
import re
import time

master_ips = []
worker_ips = []
master_count = 0
worker_count = 1
has_internet = False
docker_registry = None
docker_registry_ip = None
vip = None
lbpool = ""
join_command = ""
interface = ""
ip = ""
is_master = False
is_first_master = False
ha_proxy_installed = False
docker_registry_with_slash = ""
single_node = False
docker_registry_domain = ""
dashboard_domain = ""
pg_admin_domain = ""
use_ceph = False
ceph_mon_ips = []
ceph_user = ""
ceph_key = ""
nfs_server = ""
nfs_path = ""
use_public_ip_only = False
use_public_ip_for_dashboard = False
install_docker_registry = False
use_public_ip_for_docker_registry = False
install_pg_admin = False
base_domain = "ik8s.amprajin.in"


all_interfaces = []

# Function to execute shell commands

def validate_ipv4(ip):
    # Regular expression pattern for IPv4 validation
    pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    
    # Check if the provided IP matches the pattern
    if re.match(pattern, ip):
        return True
    else:
        return False
def validate_iprange(iprange):

    
    # Check if the format is IP/mask (CIDR notation)
    if '/' in iprange:
        ip, mask = iprange.split('/')
        if validate_ipv4(ip):
            # Validate mask
            if 0 <= int(mask) <= 32:
                return True
    # Check if the format is IP range
    elif '-' in iprange:
        start_ip, end_ip = iprange.split('-')
        if validate_ipv4(start_ip) and validate_ipv4( end_ip):
            return True
    
    return False
def execute_command(command, exit_on_error=True,timeout_seconds=300, max_retries=3):
    """Executes a shell command and returns the output and error."""
    print("\n\nExecuting command: {}".format(command))
    print("\nPlease wait...\n")

    retries = 0
    output = ""
    error = ""

    while retries < max_retries:
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            try:
                output, error = process.communicate(timeout=timeout_seconds)
                output = output.decode()
                error = error.decode()

                if output:
                    print("Output:\n")
                    print(output)

                if error:
                    print("Error occurred:\n")
                    print(error)
                    raise Exception(error)
                return output, error

            except subprocess.TimeoutExpired:
                print("Timeout occurred. Retrying...")
                process.kill()
                retries += 1

        except Exception as e:
            print(f"Error occurred: {e}")
            retries += 1

        time.sleep(1)  # Add a small delay before retrying
    print(f"Command '{command}' failed after {max_retries} retries.")
    if exit_on_error:
        print("Exiting...")
        process.kill()
        exit(1)
    return output, error


def get_lan_interface_name():
    """Returns the name of the LAN interface on Ubuntu."""
    global all_interfaces

    output, error = execute_command(
        "ip -o link show | awk -F': ' '{print $2}'")
    all_interfaces = output.splitlines()
    for line in output.splitlines():
        if 'e' in line and 'lo' not in line:
            return line


def get_lan_interface_ip():
    """Returns the IP address of the LAN interface on Ubuntu."""

    output, error = execute_command(
        f"ip addr show {interface} | grep -oP 'inet\s+\K[\d.]+'")
    lines = output.splitlines()
    if len(lines) > 0:
        if len(lines) > 1:
            print("Multiple IP addresses found for interface {}".format(interface))
            print("Please choose the IP address to be used: ")
            for i in range(len(lines)):
                print("{}: {}".format(i+1, lines[i]))
            choice = input()
            if choice.isdigit() and int(choice) <= len(lines):
                return lines[int(choice) - 1]
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
    global dashboard_domain
    global docker_registry_domain
    global pg_admin_domain
    global use_public_ip_only
    global use_public_ip_for_dashboard
    global use_public_ip_for_docker_registry
    global install_docker_registry
    global install_pg_admin
    global docker_registry_ip
    global use_ceph
    global ceph_mon_ips
    global ceph_user
    global ceph_key
    global nfs_server
    global nfs_path
    global all_interfaces
    global base_domain

    global interface
    while interface == "":
        base_domain = input("Enter the base domain to be used [defult : {}] : ".format(base_domain)) or base_domain
        interface = get_lan_interface_name()
        print("LAN interface is {} is this correct (y/n) [default: y] ?:".format(interface))
        if (input() or "y") == "n":
            print("Please choose the LAN interface to be used: ")
            for i in range(len(all_interfaces)):
                print("{}: {}".format(i+1, all_interfaces[i]))
            choice = input()
            if choice.isdigit() and int(choice) <= len(all_interfaces):
                interface = all_interfaces[int(choice) - 1]
            else:
                print("Invalid input")
                exit(1)

    while ip == "":
        ip = get_lan_interface_ip()
        print("LAN interface IP is {} is this correct (y/n) [default: y] ?".format(ip))
        if (input() or "y") == "n":
            ip = input("Enter the LAN interface IP: ")
            if not validate_ipv4(ip):
                print("Invalid ip please enter correct IP")
                ip = ""
    master_count = int(
        input("Enter the number of master nodes [default: 0] ?:").strip() or "0")
    
    
    

    if master_count > 0:
        is_master = "y" == input("Is it a master node (y/n) [default: n] ? :").strip() or "n"
        if is_master:
            master_ips.append(ip)
            if master_count == 1:
                is_first_master = True
            elif master_count>1:
                print("only one master node to be insitilized rest of them need to be joined.")
                is_first_master = "y" == input("Is it a master node to be intialized (y/n) [default: n] ?:").strip() or "n"
                while len(master_ips) < master_count:
                    print("master nodes:", master_ips)

                    node_ip = input("Enter the IP address of master node {}: ".format(len(master_ips)+1))
                    if validate_ipv4(node_ip):
                        master_ips.append(node_ip)
                    else:
                        print("Invalid ip address")

    if not is_master:
        worker_ips.append(ip)

    if master_count == 0:
        print("0 master node selected starting with single node cluster setup...")
        worker_count = 1
        is_master = True
        is_first_master = True
        single_node = True
    else:
        worker_count = int(input("Enter the number of worker nodes [defult: 1] :") or "1")
        if not worker_count>0:
            print("worker count should be greater than 0")
        while len(worker_ips) < worker_count:
            print("worker nodes:", worker_ips)
            node_ip = input("Enter the IP address of worker node {}: ".format(len(worker_ips)+1))
            if validate_ipv4(node_ip):
                worker_ips.append(node_ip)
            else:
                print("Invalid ip address")


    while True:
        has_internet = input(
            "Does the cluster have permenant internet access? (y/n) [defult: y] : ") or "y"
        if has_internet == "y" or has_internet == "n":
            break
        print("Invalid input try again !")
    has_internet = has_internet == "y"
    if not has_internet:
        install_docker_registry = input("Do you want to install harbor docker registry? (y/n) [defult: n] : ") or "n"
        install_docker_registry = install_docker_registry == "y"
        if install_docker_registry:
            docker_registry_domain = input("Enter the docker registry domain to be used [defult : harbor.{}]: ".format(base_domain)) or "harbor.{}".format(base_domain)
            docker_registry = docker_registry_domain + "/library/"
            docker_registry_ip = None
        else:
            docker_registry = input("Enter the docker registry to be used: ")
            docker_registry_ip = input("Enter the docker registry IP to be used: ")
        
        
        docker_registry_with_slash = docker_registry.endswith(
            "/") and docker_registry or docker_registry + "/"
    if master_count>1:
        while vip == "" or vip == None:
            vip = input("Enter the VIP to be used: ")
            if not validate_ipv4(vip):
                print("Invalid ip please enter correct VIP virtual ip, IPv4 :")
                vip = ""
    poolstart = ip.split(".")
    poolstart[3] = str(100)
    poolstart = ".".join(poolstart)
    while lbpool=="":
        lbpool = input(f"Enter the load balancer pool to be used [defult : {poolstart}/30] : ") or f"{poolstart}/30"
        if not validate_iprange(lbpool):
            lbpool = ""
            print ("invalid ip range use format  192.168.10.0/24 or 192.168.9.1-192.168.9.5")
    use_ceph = input("Do you want to use Ceph for storage? (y/n) [defult: n] : ") or "n"
    use_ceph = use_ceph == "y"
    if use_ceph:
        ceph_mon_ips = input(
            "Enter the Ceph monitor IPs (comma separated): ").split(",")
        ceph_user = input("Enter the Ceph user: ")
        ceph_key = input("Enter the Ceph key: ")
    else:
        while nfs_server=="":
            nfs_server = input(f"Enter the NFS server IP [defult : {ip}] : ") or f"{ip}"
            if not validate_ipv4(nfs_server):
                nfs_server ==""
                print("Invalid ip address for nfs server..")

        nfs_path = input("Enter the NFS path defult[/]:") or "/"


    use_public_ip_only = input("Do you want to use public IP only? (y/n) [defult: y] : ") or "y"
    use_public_ip_only = use_public_ip_only == "y"
    if use_public_ip_only:
        use_public_ip_for_dashboard = True
        use_public_ip_for_docker_registry = True
    else:
        use_public_ip_for_dashboard = input("Do you want to use public IP for dashboard? (y/n) [defult: n] : ") or "n"
        use_public_ip_for_dashboard = use_public_ip_for_dashboard == "y"
        if install_docker_registry:
            use_public_ip_for_docker_registry = input("Do you want to use public IP for docker registry? (y/n) [defult: n] : ") or "n"
            use_public_ip_for_docker_registry = use_public_ip_for_docker_registry == "y"


    
    dashboard_domain = input("Enter the dashboard domain to be used [defult : k8sdb.{}]: ".format(base_domain)) or "k8sdb.{}".format(base_domain)
    install_pg_admin = input("Do you want to install pg admin? (y/n) [defult: n] : ") or "n"
    install_pg_admin = install_pg_admin == "y"
    if install_pg_admin:
        pg_admin_domain = input("Enter the pg admin domain to be used [defult : pgadmin.{}]: ".format(base_domain)) or "pgadmin.{}".format(base_domain)


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
    print("dashboard_domain: {}".format(dashboard_domain))
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
    if vip:
        command = "echo \"{} master.in\" >> /etc/hosts".format(vip)
        execute_command(command)
    for i in range(len(master_ips)):
        command = "echo \"{} master{}.in\" >> /etc/hosts".format(
            master_ips[i], i+1)
        execute_command(command)
    if docker_registry and docker_registry_ip:
        command = "echo \"{} {}\" >> /etc/hosts".format(
            docker_registry_ip, docker_registry)
        execute_command(command)


# Function to install containerd
def install_containerd():
    # Check if containerd is installed
    output, error = execute_command("which curl")
    if output == "":
        execute_command("DEBIAN_FRONTEND=noninteractive sudo apt install -y curl")
    output, error = execute_command("which containerd")
    if output == "":
        # Install containerd
        # Add containerd configuration
        # Restart containerd
        # Enable containerd
        # Check containerd status
        execute_command("sudo mkdir -p /etc/containerd")
        execute_command(
            "sudo cp containerd-config.toml /etc/containerd/config.toml")
        execute_command(
            "sudo tar Cxzvf /usr/local containerd-1.6.14-linux-amd64.tar.gz")
        execute_command("sudo cp containerd.service /etc/systemd/system/containerd.service")
        execute_command("sudo systemctl daemon-reload")
        execute_command("sleep 2")
        execute_command("sudo systemctl enable containerd --now", False)
        execute_command("sleep 2")
        execute_command("sudo systemctl restart containerd", False)
        execute_command("sleep 2")
        execute_command("sudo systemctl status containerd")


    else:
        print("Containerd already installed, Please check if it is configured correctly")
        print(" warning !! recommented to unistall all dependencies before installing this")
    
    output, error = execute_command("which runc")
    if output=="":
        execute_command("sudo install -m 755 runc.amd64 /usr/local/sbin/runc")
    else:
        print("runc already installed, Please check if it is configured correctly")
        print(" warning !! recommented to unistall all dependencies before installing this")
    execute_command("sudo systemctl status containerd")

    execute_command("""cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF""")
    execute_command("sudo modprobe -a overlay br_netfilter")
    execute_command("sudo modprobe br_netfilter")
    execute_command("""cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF""")
    
    execute_command("sudo sysctl --system", False)
    # If not installed, follow the provided steps to install containerd


# Function to install Kubernetes components
def install_kubernetes():
    # Add Kubernetes GPG key
    execute_command("sudo rm -rf /etc/apt/keyrings/kubernetes-archive-keyring.gpg", False)
    execute_command(
        "curl -fsSL https://dl.k8s.io/apt/doc/apt-key.gpg | sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/kubernetes-archive-keyring.gpg")
    # Add Kubernetes apt repository
    execute_command("sudo rm -rf /etc/apt/sources.list.d/kubernetes.list", False)
    execute_command(
        "echo \"deb [signed-by=/etc/apt/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main\" | sudo tee /etc/apt/sources.list.d/kubernetes.list")
    # Install kubeadm, kubelet & kubectl
    execute_command("DEBIAN_FRONTEND=noninteractive sudo apt-get update", False)
    execute_command(
        "DEBIAN_FRONTEND=noninteractive sudo apt-get install -y  kubelet=1.25.8-00 kubeadm=1.25.8-00 kubectl=1.25.8-00")
    execute_command("DEBIAN_FRONTEND=noninteractive sudo apt-mark hold kubelet kubeadm kubectl")
    # Disable swap
    execute_command("sudo swapoff -a")
    execute_command("sudo sed -i -e '/swap/d' /etc/fstab")
    output, error = execute_command("sudo which ufw")
    if not output == "":
        # firewall allow ports 22,80,443,8443,6443,2379,2380,10250,10257,10259,30000-32767
        execute_command(
            "sudo ufw allow 22,80,443,8443,6443,2379,2380,10250,10257,10259/tcp")
        execute_command("sudo ufw allow 30000:32767/tcp")
    # Configure kubectl

# Function to install and configure Keepalived & HAProxy


def install_keepalived_haproxy():
    # Install and configure Keepalived & HAProxy on multiple master nodes if needed
    global ha_proxy_installed
    if is_master and master_count > 1:
        ha_proxy_installed = True
        execute_command("sudo apt update", False)
        execute_command(
            "DEBIAN_FRONTEND=noninteractive sudo apt install -y keepalived haproxy")
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
EOF""".format(vip=vip, interface=interface))

        execute_command("systemctl enable --now keepalived")
        execute_command("sudo systemctl status keepalived")
        execute_command(generate_haproxy_config(master_count))
        execute_command(
            "systemctl enable haproxy && systemctl restart haproxy")
        execute_command("sudo systemctl status haproxy")

# Function to create Kubernetes cluster using kubeadm


def create_kubernetes_cluster():
    # pull images
    output = None
    error = None
    # reset existing cluster
    execute_command("sudo kubeadm reset -f", False)
    if (has_internet):
        output, error = execute_command(
            "sudo kubeadm config images pull --kubernetes-version=v1.25.8")
    else:

        output, error = execute_command(
            "sudo kubeadm config images pull --image-repository {}registry.k8s.io --kubernetes-version=v1.25.8".format(docker_registry_with_slash))
    # Initialize the cluster using kubeadm
    if is_master:
        if is_first_master:
            command = "sudo kubeadm init --pod-network-cidr=192.168.0.0/16 --kubernetes-version=v1.25.8"
            if has_internet:
                command = command + \
                    " --image-repository {}registry.k8s.io".format(
                        docker_registry_with_slash)
            if ha_proxy_installed:
                command = command + " --control-plane-endpoint \"master.in:8443\""
            output, error = execute_command(command)
                # Configure kubectl
            # delete old config
            execute_command("rm -rf $HOME/.kube", False)
            execute_command("mkdir -p $HOME/.kube")
            execute_command("sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config")
            execute_command("sudo chown $(id -u):$(id -g) $HOME/.kube/config")
            if single_node:
                execute_command(
                    "kubectl taint nodes --all node-role.kubernetes.io/master-", False)
                execute_command(
                    "kubectl taint nodes --all node-role.kubernetes.io/control-plane-", False)
        else:
            join_command = input("Enter the join command: ")
            output, error = execute_command(join_command)
    else:
        join_command = input("Enter the join command: ")
        output, error = execute_command(join_command)
    # Configure kubectl
    # delete old config
    execute_command("rm -rf $HOME/.kube", False)
    execute_command("mkdir -p $HOME/.kube")
    execute_command("sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config")
    execute_command("sudo chown $(id -u):$(id -g) $HOME/.kube/config")


# Function to install Helm


def install_helm():
    # Install Helm and configure as required
    #check if helm is installed
    output, error = execute_command("which helm")
    if output == "":
        execute_command("sudo rm -rf /usr/share/keyrings/helm.gpg", False)
        execute_command(
            "curl https://baltocdn.com/helm/signing.asc | gpg --batch --yes --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null", False)
        execute_command("""DEBIAN_FRONTEND=noninteractive sudo apt-get install apt-transport-https --yes""")
        execute_command("sudo rm -rf /etc/apt/sources.list.d/helm-stable-debian.list", False)
        execute_command(
            """echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list""")
        execute_command("""DEBIAN_FRONTEND=noninteractive sudo apt-get update""", False)
        execute_command("""DEBIAN_FRONTEND=noninteractive sudo apt-get install  -y helm""")
        execute_command("""DEBIAN_FRONTEND=noninteractive sudo apt-mark hold helm""")
    else:
        print("helm already installed, Please manually check it is configured correctly")


def deploy_calico():
    execute_command(
        """helm repo add projectcalico https://docs.tigera.io/calico/charts""")
    execute_command("""helm repo update""", False)
    execute_command(
        """helm install calico projectcalico/tigera-operator --version v3.25.2 --namespace tigera-operator --create-namespace""")
    # sleep for 10 seconds
    execute_command("sleep 10", False)
    # wait till pods are deployed in namespace tigera-operator and calico-system and calico-apiserver
    # check atlease one pod in each namespace
    
    output, error = execute_command("kubectl get pods -n tigera-operator" , False)
    while output == "":
        output, error = execute_command("kubectl get pods -n tigera-operator", False)
        time.sleep(5)
    output, error = execute_command("kubectl get pods -n calico-system", False)
    while output == "":
        output, error = execute_command("kubectl get pods -n calico-system", False)
        time.sleep(5)
    output, error = execute_command("kubectl get pods -n calico-apiserver", False)
    while output == "":
        output, error = execute_command("kubectl get pods -n calico-apiserver", False)
        time.sleep(5)
    ## sleep for 10 seconds
    execute_command("sleep 10", False)
    # wait until calico is deployed
    execute_command("kubectl wait --for=condition=ready --timeout=300s pod --all -n tigera-operator", False)
    execute_command("kubectl wait --for=condition=ready --timeout=300s pod --all -n calico-apiserver", False)
    execute_command("kubectl wait --for=condition=ready --timeout=300s pod --all -n calico-system", False)




def check_status():
    # Check if all the pods are running
    execute_command("kubectl get pods --all-namespaces", False)
    # Check if all the nodes are ready
    execute_command("kubectl get nodes", False)
    # Check if the cluster is ready
    execute_command("kubectl get cs", False)
    execute_command("kubectl wait --for=condition=ready --timeout=300s pod --all -n kube-system", False)
    print("pods status after waiting")
    execute_command("kubectl get pods --all-namespaces")


def install_k8s(re_install_dependencies=False):
    # delete old namespaces
    ## check if k8s namespace exists
    if re_install_dependencies:
        output, error = execute_command("kubectl get ns k8s", False)
        if output != "":
            execute_command("kubectl delete ns k8s", False)
            ## wait until k8s is deleted
            execute_command(
                """kubectl wait --for=delete --timeout=600s namespace/k8s""")
        command = "helm upgrade -i k8s-dependencies ./k8s-dependencies -n k8s --create-namespace --set ipPool={" + lbpool + "}"
        if docker_registry:
            command = command + " --set imageRegistry={}".format(docker_registry)

        output, error = execute_command(command)

        execute_command("sleep 10")

    command = """helm upgrade -i k8s ./k8s -n k8s --create-namespace \
--set nfs-server-provisioner.storageClass.parameters.server="{}" \
--set nfs-server-provisioner.storageClass.parameters.path="{}" \
--set kubernetes-dashboard.app.ingress.hosts[0]="{}" """.format(nfs_server, nfs_path, dashboard_domain.replace("*", "k8sdb"))
    if use_public_ip_only:
        command = command + " --set kong-internal.enabled=false --set kong.enabled=true"
    loadbalancer_ip1 = lbpool.count("-") == 1 and lbpool.split("-")[0] or lbpool.split("/")[0]
    # find the next ip  after loadbalancer_ip1
    loadbalancer_ip2 = loadbalancer_ip1.split(".")
    loadbalancer_ip2[3] = str(int(loadbalancer_ip2[3]) + 1)
    loadbalancer_ip2 = ".".join(loadbalancer_ip2)
    command = command + f" --set kong-internal.service.loadBalancerIP={loadbalancer_ip2} --set kong.service.loadBalancerIP={loadbalancer_ip1}"
    if install_docker_registry:
        command = command + " --set harbor.enabled=true"
        command = command + """ --set harbor.ingress.core.hostname="{}" """.format(docker_registry_domain)
        if use_public_ip_for_docker_registry:
            command = command + " --set harbor.ingress.core.annotations.kubernetes.io/ingress.class=publicIngress"
            command = command + " --set harbor.ingress.core.annotations.cert-manager.io/cluster-issuer=cluster-issuer-public"
        else:
            command = command + " --set harbor.ingress.core.annotations.kubernetes.io/ingress.class=priviteIngress"
            command = command + " --set harbor.ingress.core.annotations.cert-manager.io/cluster-issuer=cluster-issuer-privite"
    if install_pg_admin:
        command = command + " --set pgadmin4.enabled=true"
        command = command + """ --set pgadmin4.ingress.hosts[0].host="{}" """.format(pg_admin_domain)
        email = input("Enter the email to be used for pg admin [defult : admin@{}]: ".format(base_domain)) or "admin@{}".format(base_domain)
        password = input("Enter the password to be used for pg admin [defult : admin]: ") or "admin"
        command = command + f""" --set pgadmin4.env.email={email}" """
        command = command + f""" --set pgadmin4.env.password={password}" """
        if use_public_ip_for_dashboard:
            command = command + " --set pgadmin4.ingress.annotations.kubernetes.io/ingress.class=publicIngress"
            command = command + " --set pgadmin4.ingress.annotations.cert-manager.io/cluster-issuer=cluster-issuer-public"
        else:
            command = command + " --set pgadmin4.ingress.annotations.kubernetes.io/ingress.class=priviteIngress"
            command = command + " --set pgadmin4.ingress.annotations.cert-manager.io/cluster-issuer=cluster-issuer-privite"

    
    
    if use_public_ip_for_dashboard:
        command = command + " --set kubernetes-dashboard.app.ingress.ingressClassName=publicIngress --set kubernetes-dashboard.app.ingress.issuer=cluster-issuer-public"
    output, error = execute_command(command)

    print(f"""
    update the dns entries in your dns server
    1. {dashboard_domain} : {use_public_ip_for_dashboard and loadbalancer_ip1 or loadbalancer_ip2}
    """)
    if install_docker_registry:
        print(f"""
        2. {docker_registry_domain} : {use_public_ip_for_docker_registry and loadbalancer_ip1 or loadbalancer_ip2}
        """)
    if install_pg_admin:
        print(f"""
        3. {pg_admin_domain} : {use_public_ip_for_dashboard and loadbalancer_ip1 or loadbalancer_ip2}
        """)
    print(f"""\n
    run the following commands in your master node to use kubectl

    rm -r $HOME/.kube
    mkdir -p $HOME/.kube
    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    sudo chown $(id -u):$(id -g) $HOME/.kube/config

                                     
    kubernetes cluster is installed successfully
    kubernetes dashboard url : https://{dashboard_domain}/
    
    use this command to get token

    kubectl create token admin --duration=720h


    """)
    output,e = execute_command("kubectl create token helm --duration=720h", False)


    if install_docker_registry:
        print(f"""
        docker registry url : https://{docker_registry_domain}/""")
    if install_pg_admin:
        print(f"""
        pg admin url : https://{pg_admin_domain}/""")
        print(f""" use this credentials to login to pg admin4
        email : {email}
        password : {password}""")

          



# Main function to orchestrate the setup process
def main():
    proceed = False
    while not proceed:
        collect_node_info()
        print_node_info()
        i = input(
            "\n\n Are you sure you want to proceed with the installation? (y/n/c) [defult: y]") or "y"
        if i == "y":
            proceed = True
        elif i == "c":
            print("Exiting...")
            exit(1)
    print("Starting installation...")
    print("Choose the options to be installed")
    print("1. From scratch")
    print("2. Resetting existing cluster")
    print("3. setup dashboard by removing existing")
    print("4. setup dashboard by updating existing")

    choice = input("Enter your choice [default: 1]: ") or "1"
    choice = int(choice)
    if choice == 1:
        print("Starting installation from scratch...")
    elif choice == 2:
        print("Starting installation from existing cluster... resetting")
    elif choice == 3:
        print("Starting installation from existing cluster... dashboard by removing existing")
    elif choice == 4:
        print("Starting installation from existing cluster... dashboard by updating existing")
    else:
        print("Invalid choice")
        exit(1)
    if choice == 1:
        update_hosts_file()
        install_containerd()
        install_kubernetes()
        install_keepalived_haproxy()
    if choice <= 2:
        install_helm()
        create_kubernetes_cluster()
        deploy_calico()
    check_status()
    install_k8s(choice == 3)


if __name__ == "__main__":
    main()
