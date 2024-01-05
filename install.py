#!/usr/bin/env python3
import subprocess
import re
import time
import platform
import os


import sys

master_count = 0
docker_registry = None
master_ip = "127.0.0.1"
master_node_ips = []
lbpool = "127.0.0.100/30"
join_token = ""
join_ca = ""
join_ca_key = ""
interface = ""
ip = "127.0.0.1"
is_master = False
is_first_master = False
ha_proxy_installed = False
single_node = False
docker_registry_domain = "dr.ik8s.in"
dashboard_domain = "db.ik8s.in"
use_ceph = False
use_nfs = False
use_hostpath = False
stoarage_path = ""
ceph_cluster_id = ""
ceph_mon_ips = []
ceph_user = ""
ceph_key = ""
nfs_server = ""
nfs_path = ""
use_public_ip_only = False
use_private_ip_only = False
use_public_ip_for_dashboard = False
install_docker_registry = False
use_public_ip_for_docker_registry = False
is_windows = platform.system() == "Windows"
CERT_FILE="tls.crt"
KEY_FILE = "tls.key"

all_interfaces = []
node_join_command_info = ""
# Function to execute shell commands

def iptohostname(ip):
    return ip.replace(".", "-")
def install(package):
    try:
        import importlib
        importlib.import_module(package)
        print(f"{package} is already installed.")
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"{package} has been installed.")

def format_file(src, repalces =[],dest=None):
    with open(src, 'r') as file:
        file_content = file.read()
    modified_content = file_content
    for find, replace in repalces:
        modified_content = modified_content.replace(find, replace)
    if dest == None:
        dest = src
    with open(dest, 'w') as file:
        file.write(modified_content)
def check_installed(name):
    import shutil
    path = shutil.which(name)
    if path:
        print(f"{name} already installed")
        return True
    else:
        print(f"{name} not installed")
        return False

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
    if type(command) == list:
        command = " && ".join(command)
    elif type(command) == str:
        command = command.strip()
    else:
        print("Invalid command type")
        exit(1)
    if command == "":
        return "", ""
    print("\n\nExecuting command: {}".format(command))
    print("\n\nPlease wait!\n")

    retries = 0
    output = ""
    error = ""

    while retries < max_retries:
        if retries > 0:
            print("\n\n Retrying... \n\n")
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            try:
                output, error = process.communicate(timeout=timeout_seconds)
                output = output.decode()
                error = error.decode()

                if output:
                    print("command output:\n\n\n")
                    print(output)
                    print("\n\n\n")
                    if error:
                        print("command error/warning:\n\n\n")
                        print(error)
                        print("\n\n\n")

                elif error:
                    raise Exception(error)
                return output, error

            except subprocess.TimeoutExpired:
                print("\n\n\nTimeout occurred.")
                process.kill()
                retries += 1

        except Exception as e:
            print("\n\n\n\nError occurred:\n")
            print(e)
            print("\n\n\n\n")
            process.kill()
            retries += 1
        if max_retries > 3:
            time.sleep(retries * 10)
        time.sleep(1)  # Add a small delay before retrying
    print(f"Command \n\n'{command}' \n\nfailed after {max_retries} retries.")
    if exit_on_error:
        print("\n\n\nExiting...")
        exit(1)
    return output, error


def get_lan_interface_name():
    
    """Returns the name of the LAN interface on Ubuntu."""
    global all_interfaces
    global interface
    install("psutil")
    import psutil
    
    # Get a list of all the network interfaces
    all_interfaces =  list(psutil.net_if_addrs().keys())
    # Get the LAN interface name
    interfaces = [interface for interface in all_interfaces if interface.startswith("en")]
    if len(interfaces) > 0:
        interface = interfaces[0]
        return interface
    else:
        print("\n\nError getting LAN interface name returning first interface")
        interface = all_interfaces[0]
        return interface


def get_lan_interface_ip():
    
    """Returns the IP address of the LAN interface on Ubuntu."""
    global interface
    install("psutil")
    import psutil


    lines = psutil.net_if_addrs()[interface]
    # get all ip address of the interface
    lines = [line for line in lines if line.family == 2]
    lines = [line.address for line in lines]
    print(lines)
    if len(lines) > 0:
        if len(lines) > 1:
            print("\n\n\nMultiple IP addresses found for interface {}".format(interface))
            print("\nPlease choose the IP address to be used: \n\n")
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
        print("\n\nError getting IP address for interface {}".format(interface))
        exit(1)


def generate_haproxy_config():
    config = ""
    for ip in master_node_ips:
        host = iptohostname(ip)
        config += f"    server master{host} master{host}.in:6443 check fall 3 rise 2\n"

    return config
# Function to collect node information


def collect_node_info():
    # Collect node information here based on the provided data
    global master_count
    global interface
    global ip
    global is_master
    global is_first_master
    global ha_proxy_installed
    global single_node
    global docker_registry
    global master_ip
    global master_node_ips
    global all_interfaces
    global is_windows
    global join_ca
    global join_token
    global join_ca_key


    global interface

    master_ip = input("Control-plane IP or Virtual IP \n incase of loadbalanced masternoads (default:127.0.0.1)): ") or master_ip
    while not validate_ipv4(master_ip):
            print("\nInvalid ip please enter correct IP :")
            master_ip = input()
    
    is_master = input("\nIs it a master node (y/n) [default: n] ? :").strip() or "n"
    is_master = is_master == "y"
    if is_master:
        print("\n!Only one master node to be insitilized rest of them need to be joined.\n")
        is_first_master = input("Is it the first master node (y/n) [default: y] ? :").strip() or "y"
        is_first_master = is_first_master == "y"
    else:
        ha_proxy_installed = input("is it have a load balanced contrl-plne with host 'master.in:8443' (y/n)? [defult n] :").strip() or "n"

    if not is_master or (is_master and not is_first_master):
        while join_token == "" or join_token == None:
            join_token = input("Enter the join token (--token): ")
            if not join_token:
                print("Invalid join token please enter correct join token (--token) :")
                join_token = ""
        while join_ca == "" or join_ca == None:
            join_ca = input("Enter the join ca (--discovery-token-ca-cert-hash): ")
            if not join_ca:
                print("Invalid join ca please enter correct join ca  (--discovery-token-ca-cert-hash)")
                join_ca = ""
        if is_master and not is_first_master:
            while join_ca_key == "" or join_ca_key == None:
                join_ca_key = input("Enter the join ca key (--discovery-token-unsafe-skip-ca-verification): ")
                if not join_ca_key:
                    print("Invalid join ca key please enter correct join ca key (--discovery-token-unsafe-skip-ca-verification)")
                    join_ca_key = ""
        else:
            return
    
    print("\n !! 0 master node means single node cluster setup...!!\n")
    master_count = int(
        input("Enter the number of master nodes [default: 0] ?:").strip() or "0")
    if master_count == 0:
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("\t"*3)
        print(" entering single node cluster setup... \n")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        single_node = True
        is_first_master = True
    elif master_count > 1:
        ha_proxy_installed = True
    else:
        ha_proxy_installed = input("Is HAProxy need to be installed for estending master nodes? :").strip() or "n"
        ha_proxy_installed = ha_proxy_installed == "y"
        
        
    if ha_proxy_installed:
        while interface == "":
            interface = get_lan_interface_name()
            print("""LAN interface is " {} " is this correct (y/n) [default: y] ?:""".format(interface))
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

        ip = get_lan_interface_ip()
        print("LAN interface IP is {} is this correct (y/n) [default: y] ?".format(ip))
        if (input() or "y") == "n":
            ip = input("Enter the LAN interface IP: ")
            while validate_ipv4(ip):
                print("Invalid ip please enter correct IP")
                ip = input()

        master_node_ips.append(ip)
        while len(master_node_ips) < master_count:
            print("master nodes:", master_node_ips)

            node_ip = input("Enter the IP address of master node {}: ".format(len(master_node_ips)+1))
            if validate_ipv4(node_ip):
                master_node_ips.append(node_ip)
            else:
                print("Invalid ip address")

    if not is_first_master:
        return

    docker_registry = input("Enter the docker registry to be used: to bootstrap the cluster without internet access (keep balnk if not required) :")
    if docker_registry == "":
        docker_registry = None

def collect_cluster_info():
    # Collect node information here based on the provided data
    global ha_proxy_installed
    global lbpool
    global dashboard_domain
    global docker_registry_domain
    global use_public_ip_only
    global use_public_ip_for_dashboard
    global use_public_ip_for_docker_registry
    global install_docker_registry
    global use_ceph
    global ceph_mon_ips
    global ceph_user
    global ceph_key
    global ceph_cluster_id
    global nfs_server
    global nfs_path
    global use_private_ip_only
    global is_windows
    global is_first_master
    global is_master
    global use_nfs
    global use_hostpath
    global stoarage_path

    is_master = True
    is_first_master = True
    print("\n"*10)
    print("========================= ik8s Kubernets Cluster setup =========================\n\n")
    print("\n\nPlease provide the following information to instilize kubernets dependencies and dashbords:\n\n")
    print("\n\n--------------------------------------------------------------------------------\n\n")
    install_docker_registry = input("Do you want to install harbor docker registry? (y/n) [defult: n] : ") or "n"
    install_docker_registry = install_docker_registry == "y"
    if install_docker_registry:
        docker_registry_domain = input("Enter the docker registry domain to be used [defult : {}]: ".format(docker_registry_domain)) or docker_registry_domain

    if not is_windows:
        poolstart = ip.split(".")
        poolstart[3] = str(100)
        poolstart = ".".join(poolstart)
        lbpool = f"{poolstart}/30"
    lbpool = input(f"Enter the load balancer pool to be used [defult : {lbpool}] : ") or lbpool
    while not validate_iprange(lbpool):
        print ("invalid ip range use format  192.168.10.0/24 or 192.168.9.1-192.168.9.5")
        lbpool = input(f"Enter valid ip pool ")
    use_ceph = input("Do you want to use Ceph for storage? (y/n) [defult: n] : ") or "n"
    use_ceph = use_ceph == "y"
    if use_ceph:
        ceph_mon_ips = input(
            "Enter the Ceph monitor IPs (comma separated): ").split(",")
        ceph_user = input("Enter the Ceph user: ")
        ceph_key = input("Enter the Ceph key: ")
        ceph_cluster_id = input("Enter the Ceph cluster ID: ")
    else:
        use_nfs = input("Do you want to use NFS for storage? which create nfs storage class (y/n) [defult: n] : ") or "n"
        use_nfs = use_nfs == "y"
        if use_nfs:
            while nfs_server=="":
                nfs_server = input(f"Enter the NFS server IP [defult : {ip}] : ") or f"{ip}"
                if not validate_ipv4(nfs_server):
                    nfs_server ==""
                    print("Invalid ip address for nfs server..")

            nfs_path = input("Enter the NFS path defult[/]:") or "/"
        use_hostpath = input("Do you want to use openEBS for storage? which create Storage Class  openebs-hostpath (y/n) [defult: n] : ") or "n"
        use_hostpath = use_hostpath == "y"
        if use_hostpath:
            stoarage_path = input("Enter the hostpath to be used [defult : /var/openebs/local] : ") or "/var/openebs/local"




    use_public_ip_only = input("Do you want to use public IP only? (y/n) [defult: y] : ") or "y"
    use_public_ip_only = use_public_ip_only == "y"
    if use_public_ip_only:
        use_public_ip_for_dashboard = True
        use_public_ip_for_docker_registry = True
    else:
        use_private_ip_only = input("Do you want to use private IP only? (y/n) [defult: n] : ") or "n"
        use_private_ip_only = use_private_ip_only == "y"
        if not use_private_ip_only:
            use_public_ip_for_dashboard = input("Do you want to use public IP for dashboard? (y/n) [defult: n] : ") or "n"
            use_public_ip_for_dashboard = use_public_ip_for_dashboard == "y"
            if install_docker_registry:
                use_public_ip_for_docker_registry = input("Do you want to use public IP for docker registry? (y/n) [defult: n] : ") or "n"
                use_public_ip_for_docker_registry = use_public_ip_for_docker_registry == "y"
        else:
            use_public_ip_for_dashboard = False
            use_public_ip_for_docker_registry = False


    
    dashboard_domain = input("Enter the dashboard domain to be used [defult : {}]: ".format(dashboard_domain)) or dashboard_domain


def print_node_info():
    # Print collected node information
    print("\n\n ========================= Cluster Setup Information =========================\n\n")
    print("single_node: {}".format(single_node))
    print("is_master: {}".format(is_master))
    if is_master:
        print("ha_proxy_installed: {}".format(ha_proxy_installed))
        print("is_first_master: {}".format(is_first_master))
        if ha_proxy_installed:
            print("master_count: {}".format(master_count))
            print("master_node_ips: {}".format(master_node_ips))
            print("interface: {}".format(interface))
            print("ip: {}".format(ip))
            print("master_ip for haproxy (master loadbalancing VIP): {}".format(master_ip))
        if is_first_master:
            print("docker_registry: {}".format(docker_registry))
            print("lbpool: {}".format(lbpool))
            print("dashboard_domain: {}".format(dashboard_domain))
            print("use_ceph: {}".format(use_ceph))
            if use_ceph:
                print("ceph_mon_ips: {}".format(ceph_mon_ips))
                print("ceph_user: {}".format(ceph_user))
                print("ceph_key: {}".format(ceph_key))
            else:
                print("nfs_server: {}".format(nfs_server))
                print("nfs_path: {}".format(nfs_path))
            print("use_public_ip_only: {}".format(use_public_ip_only))
            print("use_public_ip_for_dashboard: {}".format(use_public_ip_for_dashboard))
            print("use_public_ip_for_docker_registry: {}".format(use_public_ip_for_docker_registry))
            print("install_docker_registry: {}".format(install_docker_registry))
            print("docker_registry_domain: {}".format(docker_registry_domain))
            print("use_private_ip_only: {}".format(use_private_ip_only))
    print("===============================================================================\n\n\n")
    print("is_windows: {}".format(is_windows))
    proceed = False
    while not proceed:
        i = input(
            "\n\n Are you sure you want to proceed with the installation? (y/n/c) [defult: y]") or "y"
        if i == "y":
            proceed = True
        elif i == "c":
            print("Exiting...")
            exit(1)


# Function to add entries to /etc/hosts

def update_hosts_file_windows():
    print("updating hosts file on windows")
    print("todo")
    pass

def update_hosts_file():
    # Add entries to /etc/hosts based on collected node information
    # Add entries for master nodes
    # Add entries for load balancer
    # Add entries for registry
    # Add entries for VIP as master.in
    if master_ip and ha_proxy_installed:
        command = "echo \"# added by ik8s\" >> /etc/hosts"
        execute_command(command)
        command = "echo \"{} master.in\" >> /etc/hosts".format(master_ip)
        execute_command(command)
    if ha_proxy_installed and is_master:
        for ip in master_node_ips:
            command = "echo \"{} master{}.in\" >> /etc/hosts".format(
                ip, iptohostname(ip))
            execute_command(command)



def install_docker_windows():
    print("installing docker on windows")
    print("todo")
    pass

# Function to install containerd
def install_containerd():
    # Check if containerd is installed
    if not check_installed("curl"):
        execute_command("DEBIAN_FRONTEND=noninteractive sudo apt install -y curl", False, max_retries=1)
    if not check_installed("containerd"):
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
        time.sleep(2)
        execute_command("sudo systemctl enable containerd --now", False, max_retries=1)
        time.sleep(2)
        execute_command("sudo systemctl restart containerd", False, max_retries=1)
        time.sleep(2)
        execute_command("sudo systemctl status containerd")


    else:
        print("Containerd already installed, Please check if it is configured correctly")
        print(" warning !! recommented to unistall all dependencies before installing this")
    
    if not check_installed("runc"):
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
    
    execute_command("sudo sysctl --system", False, max_retries=1)
    # If not installed, follow the provided steps to install containerd


def install_kubernetes_windows():
    print("installing kubernetes on windows")
    print("todo")
    pass
# Function to install Kubernetes components
def install_kubernetes():
    # Add Kubernetes GPG key
    execute_command("sudo rm -rf /etc/apt/keyrings/kubernetes-apt-keyring.gpg", False, max_retries=1)
    execute_command(
        "curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.25/deb/Release.key | sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg")
    # Add Kubernetes apt repository
    execute_command("sudo rm -rf /etc/apt/sources.list.d/kubernetes.list", False, max_retries=1)
    execute_command(
        "echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.25/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list")
    # Install kubeadm, kubelet & kubectl
    execute_command("DEBIAN_FRONTEND=noninteractive sudo apt-get update", False, max_retries=1)
    execute_command(
        "DEBIAN_FRONTEND=noninteractive sudo apt-get install -y  kubelet=1.25.8-1.1 kubeadm=1.25.8-1.1 kubectl=1.25.8-1.1")
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

def install_keepalived_haproxy_windows():
    print("installing keepalived and haproxy on windows")
    print("todo")
    pass

def install_keepalived_haproxy():
    # Install and configure Keepalived & HAProxy on multiple master nodes if needed
    global ha_proxy_installed
    if ha_proxy_installed and is_master:
        execute_command("sudo apt update", False, max_retries=1)
        execute_command(
            "DEBIAN_FRONTEND=noninteractive sudo apt install -y keepalived haproxy", False, max_retries=1)
        format_file("check_apiserver.sh", [("_VIP_", master_ip)], "/etc/keepalived/check_apiserver.sh")
        execute_command("sudo chmod +x /etc/keepalived/check_apiserver.sh")

        format_file("keepalived.conf", [("_INTERFACE_", interface),("_VIP_",master_ip)], "/etc/keepalived/keepalived.conf")
        if is_first_master:
            format_file("keepalived.conf", [("BACKUP", "MASTER "),("100","200")], "/etc/keepalived/keepalived.conf")

        execute_command("systemctl enable --now keepalived", False, max_retries=1)
        time.sleep(30)
        execute_command("sudo systemctl status keepalived", max_retries=10)
        configuratin = generate_haproxy_config()
        format_file("haproxy.cfg", [("_SERVER_", configuratin)], "/etc/haproxy/haproxy.cfg")
        execute_command(
            "systemctl enable haproxy && systemctl restart haproxy", False, max_retries=1)
        time.sleep(30)
        execute_command("sudo systemctl status haproxy", max_retries=10)

# Function to create Kubernetes cluster using kubeadm

def create_kubernetes_cluster_windows():
    print("creating kubernetes cluster on windows")
    print("todo")
    pass
def create_kubernetes_cluster():
    # pull images
    global node_join_command_info
    output = None
    error = None
    # reset existing cluster
    execute_command("sudo kubeadm reset -f",False, max_retries=1)
    if docker_registry:
        output, error = execute_command(
            "sudo kubeadm config images pull --image-repository {} --kubernetes-version=v1.25.8".format(docker_registry))
    else:
        output, error = execute_command(
            "sudo kubeadm config images pull --kubernetes-version=v1.25.8")

    # Initialize the cluster using kubeadm
    if is_master:
        if is_first_master:
            command = "sudo kubeadm init --pod-network-cidr=192.168.0.0/16 --kubernetes-version=v1.25.8 --upload-certs "
            if docker_registry:
                command = command + \
                    " --image-repository {}".format(
                        docker_registry)
            if ha_proxy_installed:
                command = command + " --control-plane-endpoint=\"master.in:8443\""
            output, error = execute_command(command, False,max_retries=1)
            start_index = output.find("You can now join")
            node_join_command_info = output[start_index:]

                # Configure kubectl
            # delete old config
            execute_command("rm -rf $HOME/.kube", False, max_retries=1)
            execute_command("mkdir -p $HOME/.kube")
            execute_command("sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config")
            execute_command("sudo chown $(id -u):$(id -g) $HOME/.kube/config")
            if single_node:
                execute_command(
                    "kubectl taint nodes --all node-role.kubernetes.io/master-", False)
                execute_command(
                    "kubectl taint nodes --all node-role.kubernetes.io/control-plane-", False)
        else:
            join_command = "sudo kubeadm join master.in:8443 --token {} --discovery-token-ca-cert-hash {} --control-plane --certificate-key {}".format(join_token, join_ca, join_ca_key)
            output, error = execute_command(join_command)
            exit(0)
    else:
        control_plan = ha_proxy_installed and "master.in:8443" or master_ip+":6443"
        join_command = f"sudo kubeadm join {control_plan} --token {join_token} --discovery-token-ca-cert-hash {join_ca}"
        output, error = execute_command(join_command)
        exit(0)


# Function to install Helm

def install_helm_windows():
    if not is_first_master:
        return
    print("installing helm on windows")
    print("todo")
    pass

def install_helm():
    # Install Helm and configure as required
    #check if helm is installed
    if not is_first_master:
        return
    if not check_installed("helm"):
        execute_command("sudo rm -rf /usr/share/keyrings/helm.gpg", False, max_retries=1)
        execute_command(
            "curl https://baltocdn.com/helm/signing.asc | gpg --batch --yes --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null", False)
        execute_command("""DEBIAN_FRONTEND=noninteractive sudo apt-get install apt-transport-https --yes""")
        execute_command("sudo rm -rf /etc/apt/sources.list.d/helm-stable-debian.list", False, max_retries=1)
        execute_command(
            """echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list""")
        execute_command("""DEBIAN_FRONTEND=noninteractive sudo apt-get update""", False, max_retries=1)
        execute_command("""DEBIAN_FRONTEND=noninteractive sudo apt-get install  -y helm""")
        execute_command("""DEBIAN_FRONTEND=noninteractive sudo apt-mark hold helm""")
    else:
        print("helm already installed, Please manually check it is configured correctly")


def deploy_calico():
    if not is_first_master:
        return
    execute_command(
        """helm repo add projectcalico https://docs.tigera.io/calico/charts""")
    execute_command("""helm repo update""", False, max_retries=1)
    execute_command(
        """helm upgrade -i calico projectcalico/tigera-operator --version v3.25.2 --namespace tigera-operator --create-namespace --wait""")
    # sleep for 30 seconds
    time.sleep(30)
    # wait till pods are deployed in namespace tigera-operator and calico-system and calico-apiserver
    # check atlease one pod in each namespace
    
    output, error = execute_command("kubectl get pods -n tigera-operator" , False, max_retries=1)
    while output == "":
        output, error = execute_command("kubectl get pods -n tigera-operator", False, max_retries=1)
        time.sleep(5)
    output, error = execute_command("kubectl get pods -n calico-system", False, max_retries=1)
    while output == "":
        output, error = execute_command("kubectl get pods -n calico-system", False, max_retries=1)
        time.sleep(5)
    output, error = execute_command("kubectl get pods -n calico-apiserver", False, max_retries=1)
    while output == "":
        output, error = execute_command("kubectl get pods -n calico-apiserver", False, max_retries=1)
        time.sleep(5)
    ## sleep for 10 seconds
    time.sleep(10)
    # wait until calico is deployed
    execute_command("kubectl wait --for=condition=ready --timeout=300s pod --all -n tigera-operator", False, max_retries=5)
    execute_command("kubectl wait --for=condition=ready --timeout=300s pod --all -n calico-apiserver", False, max_retries=5)
    execute_command("kubectl wait --for=condition=ready --timeout=300s pod --all -n calico-system", False, max_retries=5)




def check_status():
    # Check if all the pods are running
    execute_command("kubectl get pods --all-namespaces", False,max_retries=1)
    # Check if all the nodes are ready
    execute_command("kubectl get nodes", False,max_retries=1)
    # Check if the cluster is ready
    execute_command("kubectl get cs", False,max_retries=1)
    execute_command("kubectl wait --for=condition=ready --timeout=300s pod --all -n kube-system", False,timeout_seconds=None)
    print("pods status after waiting")
    execute_command("kubectl get pods --all-namespaces")

def install_dependencies():
    execute_command("kubectl delete StorageClass nfs -n k8s", False,timeout_seconds=None)
    print("\n"*10)
    print("lbpool : ",lbpool)
    print("\n"*10)
    command = f"""helm upgrade -i k8s-dependencies ./k8s-dependencies -n k8s --wait --create-namespace --set ipPool="{{{lbpool}}}" """
    if use_ceph:
        command = command + """ --set ceph-csi-cephfs.enabled=true """
        command = command + """--set ceph-csi-cephfs.csiConfig[0].monitors="{""" + ",".join(ceph_mon_ips) + """"}" """
        command = command + """--set ceph-csi-cephfs.csiConfig[0].monitors="{}" """.format(ceph_cluster_id)
        command = command + """--set ceph-csi-cephfs.csiConfig[0].cephFS.subvolumeGroup="csi" """
        command = command + """--set ceph-csi-cephfs.csiConfig[0].cephFS.netNamespaceFilePath="{{{{ .kubeletDir }}}}/plugins/ {{{{ .driverName }}}}/net" """
        command = command + """--set ceph-csi-cephfs.secret.adminID={} --set ceph-csi-cephfs.secret.adminKey={}" """.format(ceph_user, ceph_key)

        command = command + """ --set ceph-csi-rbd.enabled=true """
        command = command + """--set ceph-csi-rbd.csiConfig[0].monitors="{""" + ",".join(ceph_mon_ips) + """"}" """
        command = command + """--set ceph-csi-rbd.csiConfig[0].monitors="{}" """.format(ceph_cluster_id)
        command = command + """--set ceph-csi-rbd.csiConfig[0].rbd.netNamespaceFilePath="{{{{ .kubeletDir }}}}/plugins/ {{{{ .driverName }}}}/net" """
        command = command + """--set ceph-csi-rbd.secret.userID={} --set ceph-csi-rbd.secret.userKey={}" """.format(ceph_user, ceph_key)

    if use_nfs:
        command = command + """ --set nfs.enabled=true --set nfs.nfs.server="{}" --set nfs.nfs.path="{}" """.format(nfs_server, nfs_path)
    if use_hostpath:
        command = command + """ --set openebs.enabled=true --set openebs.localprovisioner.basePath="{}" """.format(stoarage_path)

    if docker_registry:
        command = command + """ --set imageRegistry="{}" """.format(docker_registry)
        if use_nfs:
            command = command + """ --set nfs.image.repository="{}/registry.k8s.io/sig-storage/nfs-subdir-external-provisioner" """.format(docker_registry)
        

    output, error = execute_command(command,timeout_seconds=None)

    time.sleep(10)

def install_k8s():
    # delete old namespaces
    ## check if k8s namespace exists
    command = """helm upgrade -i k8s ./k8s -n k8s --create-namespace --wait \
--set kubernetes-dashboard.app.ingress.hosts[0]="{}" """.format(dashboard_domain)
    if use_public_ip_only or use_private_ip_only:
        command = command + " --set kong-internal.enabled=false --set kong.enabled=true"
        if use_private_ip_only:
            command = command + " --set kong.ingressController.ingressClass=pvting"
    
    if not use_public_ip_only:
        # check  certificate and key exists and it was modified more than 5 years ago
        if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE) or (time.time() - os.path.getmtime(CERT_FILE)) > 157680000:
            print(" certificate and key does not exists or it was modified more than 5 years ago")
            exit(1)
        # delete old secret
        execute_command("kubectl delete secret ca-key-pair -n k8s", False)    
        # create secret from file using kubectl
        execute_command("kubectl create secret tls ca-key-pair --cert={} --key={} -n k8s".format(CERT_FILE, KEY_FILE), False)

    loadbalancer_ip1 = lbpool.count("-") == 1 and lbpool.split("-")[0] or lbpool.split("/")[0]
    # find the next ip  after loadbalancer_ip1
    loadbalancer_ip2 = loadbalancer_ip1.split(".")
    loadbalancer_ip2[3] = str(int(loadbalancer_ip2[3]) + 1)
    loadbalancer_ip2 = ".".join(loadbalancer_ip2)
    command = command + f" --set kong-internal.service.loadBalancerIP={loadbalancer_ip2} --set kong.service.loadBalancerIP={loadbalancer_ip1}"
    if install_docker_registry:
        command = command + " --set harbor.enabled=true"
        command = command + """ --set harbor.ingress.core.hostname="{}" """.format(docker_registry_domain)
        command = command + """ --set harbor.adminPassword="admin123" """
        if use_public_ip_for_docker_registry:
            command = command + """ --set harbor.ingress.core.ingressClassName=pubing"""
            command = command + """ --set harbor.ingress.core.annotations."cert-manager\\.io/cluster-issuer"=cluster-issuer-public"""
        else:
            command = command + """ --set harbor.ingress.core.ingressClassName=pvting"""
            command = command + """ --set harbor.ingress.core.annotations."cert-manager\\.io/cluster-issuer"=cluster-issuer-private"""

   
    
    if use_public_ip_for_dashboard:
        command = command + " --set kubernetes-dashboard.app.ingress.ingressClassName=pubing --set kubernetes-dashboard.app.ingress.issuer=cluster-issuer-public"
    else:
        command = command + " --set kubernetes-dashboard.app.ingress.ingressClassName=pvting --set kubernetes-dashboard.app.ingress.issuer=cluster-issuer-private"
    output, error = execute_command(command, timeout_seconds=None)

    print(f"""
    update the dns entries in your dns server
    1. {dashboard_domain} : {use_public_ip_for_dashboard and loadbalancer_ip1 or loadbalancer_ip2}
    """)
    if install_docker_registry:
        print(f"""
        2. {docker_registry_domain} : {use_public_ip_for_docker_registry and loadbalancer_ip1 or loadbalancer_ip2}
        """)
    print(f"""\n

kubernetes cluster is installed successfully
kubernetes dashboard url : https://{dashboard_domain}/
    
use this command to get token for login to dashboard
    kubectl create token admin-user --duration=720h
    kubectl create token guest-user --duration=7200h

run the following commands in your master node to use kubectl

rm -r $HOME/.kube
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
          
{node_join_command_info}
                                     


""")


    if install_docker_registry:
        print(f"""
        docker registry url : https://{docker_registry_domain}/""")


          



# Main function to orchestrate the setup process
def main():
    
    print("\n"*100)
    print("========================= ik8s Kubernets Cluster setup =========================\n\n")
    print("\n\nWelcome to ik8s Kubernetes Cluster setup. Please enetr proper values to proceed:\n\n")
    print("\n\n--------------------------------------------------------------------------------\n\n")
    print("Choose the options to be installed")
    print("_____________________________________")
    print("1. From scratch")
    print("2. Resetting existing cluster")
    print("3. upgrade existsing clcuster")
    choice = input("Enter your choice [default: 1]: ") or "1"
    choice = int(choice)
    
    if choice <1 :
        print("Invalid choice")
        exit(1)
    if choice == 1:
        print("Starting installation from scratch...")
        collect_node_info()
        print_node_info()
        if is_windows:
            update_hosts_file_windows()
            install_docker_windows()
            install_kubernetes_windows()
            install_keepalived_haproxy_windows()
        else:
            update_hosts_file()
            install_containerd()
            install_kubernetes()
            install_keepalived_haproxy()
    if choice <= 2:
        if choice == 2:
            print("Starting installation from existing cluster... resetting")
            collect_node_info()
            print_node_info()
        if is_windows:
            install_helm_windows()
            create_kubernetes_cluster_windows()
        else:
            install_helm()
            create_kubernetes_cluster()
            deploy_calico()
        if is_first_master:
            collect_cluster_info()
            install_dependencies()
            install_k8s()
    
    elif choice == 3:
        print("Starting installation from existing cluster..")
        collect_cluster_info()
        print_node_info()
        install_dependencies()
        install_k8s()
    else:
        print("Invalid choice")
        exit(1)



if __name__ == "__main__":
    main()
