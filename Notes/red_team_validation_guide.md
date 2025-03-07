# Red Team Validation Guide for Elastic Detection Rules

This guide provides step-by-step instructions for testing Elastic detection rules in a controlled environment. Each section includes detailed procedures to safely trigger detection rules, allowing security teams to validate their detection capabilities.

## Table of Contents

1. [SSH and Container Security](#ssh-and-container-security)
   - [SSH Connection Established Inside A Running Container](#ssh-connection-established-inside-a-running-container)
   - [SSH Process Launched From Inside A Container](#ssh-process-launched-from-inside-a-container)
   - [SSH Authorized Keys File Modified Inside a Container](#ssh-authorized-keys-file-modified-inside-a-container)
   - [Potential Execution via XZBackdoor](#potential-execution-via-xzbackdoor)
   - [Potential SSH Brute Force Detected on Privileged Account](#potential-ssh-brute-force-detected-on-privileged-account)
   - [SSH Authorized Keys File Modification](#ssh-authorized-keys-file-modification)
   - [SSH Key Generated via ssh-keygen](#ssh-key-generated-via-ssh-keygen)
   - [Network Connection from SSH Daemon Child Process](#network-connection-from-ssh-daemon-child-process)
   - [Unusual SSHD Child Process](#unusual-sshd-child-process)
   - [Potential Malware-Driven SSH Brute Force Attempt](#potential-malware-driven-ssh-brute-force-attempt)

2. [Container Security](#container-security)
   - [Sensitive Files Compression Inside A Container](#sensitive-files-compression-inside-a-container)
   - [File Made Executable via Chmod Inside A Container](#file-made-executable-via-chmod-inside-a-container)
   - [Privileged Docker Container Creation](#privileged-docker-container-creation)
   - [Egress Connection from Entrypoint in Container](#egress-connection-from-entrypoint-in-container)

3. [System Modification and Persistence](#system-modification-and-persistence)
   - [Hosts File Modified](#hosts-file-modified)
   - [Modification of Standard Authentication Module or Configuration](#modification-of-standard-authentication-module-or-configuration)
   - [Elastic Agent Service Terminated](#elastic-agent-service-terminated)
   - [Kernel Module Removal](#kernel-module-removal)
   - [Dynamic Linker Creation or Modification](#dynamic-linker-creation-or-modification)
   - [Dynamic Linker (ld.so) Creation](#dynamic-linker-ldso-creation)
   - [Potential Persistence via File Modification](#potential-persistence-via-file-modification)
   - [Potential Suspicious File Edit](#potential-suspicious-file-edit)
   - [Boot File Copy](#boot-file-copy)
   - [Dracut Module Creation](#dracut-module-creation)
   - [Initramfs Unpacking via unmkinitramfs](#initramfs-unpacking-via-unmkinitramfs)

4. [Package Manager Manipulation](#package-manager-manipulation)
   - [Suspicious APT Package Manager Execution](#suspicious-apt-package-manager-execution)
   - [APT Package Manager Configuration File Creation](#apt-package-manager-configuration-file-creation)
   - [Suspicious APT Package Manager Network Connection](#suspicious-apt-package-manager-network-connection)
   - [DPKG Package Installed by Unusual Parent Process](#dpkg-package-installed-by-unusual-parent-process)
   - [Unusual DPKG Execution](#unusual-dpkg-execution)
   - [DNF Package Manager Plugin File Creation](#dnf-package-manager-plugin-file-creation)
   - [RPM Package Installed by Unusual Parent Process](#rpm-package-installed-by-unusual-parent-process)
   - [Yum Package Manager Plugin File Creation](#yum-package-manager-plugin-file-creation)

5. [Obfuscation and Encoding](#obfuscation-and-encoding)
   - [Base64 Decoded Payload Piped to Interpreter](#base64-decoded-payload-piped-to-interpreter)
   - [Unusual Base64 Encoding/Decoding Activity](#unusual-base64-encodingdecoding-activity)
   - [Potential Hex Payload Execution](#potential-hex-payload-execution)
   - [Suspicious Content Extracted or Decompressed via Funzip](#suspicious-content-extracted-or-decompressed-via-funzip)

6. [Network and Web Server Activity](#network-and-web-server-activity)
   - [Network Activity Detected via Kworker](#network-activity-detected-via-kworker)
   - [Network Connection via Recently Compiled Executable](#network-connection-via-recently-compiled-executable)
   - [Network Connection from Binary with RWX Memory Region](#network-connection-from-binary-with-rwx-memory-region)
   - [Openssl Client or Server Activity](#openssl-client-or-server-activity)
   - [Web Server Spawned via Python](#web-server-spawned-via-python)
   - [Simple HTTP Web Server Creation](#simple-http-web-server-creation)
   - [Simple HTTP Web Server Connection](#simple-http-web-server-connection)

7. [Reverse Shell and Command Execution](#reverse-shell-and-command-execution)
   - [Potential Reverse Shell via Background Process](#potential-reverse-shell-via-background-process)
   - [Potential Reverse Shell via Child](#potential-reverse-shell-via-child)
   - [Potential Reverse Shell via Java](#potential-reverse-shell-via-java)
   - [Process Backgrounded by Unusual Parent](#process-backgrounded-by-unusual-parent)

8. [Hidden Files and Privilege Escalation](#hidden-files-and-privilege-escalation)
   - [Creation of Hidden Files and Directories via CommandLine](#creation-of-hidden-files-and-directories-via-commandline)
   - [Hidden Directory Creation via Unusual Parent](#hidden-directory-creation-via-unusual-parent)
   - [Directory Creation in /bin directory](#directory-creation-in-bin-directory)
   - [SUID/SGID Bit Set](#suidsgid-bit-set)
   - [SUID/SGUID Enumeration Detected](#suidsguid-enumeration-detected)

9. [Git and NetworkManager Hooks](#git-and-networkmanager-hooks)
   - [Git Hook Created or Modified](#git-hook-created-or-modified)
   - [Git Hook Command Execution](#git-hook-command-execution)
   - [Git Hook Child Process](#git-hook-child-process)
   - [Git Hook Egress Network Connection](#git-hook-egress-network-connection)
   - [NetworkManager Dispatcher Script Creation](#networkmanager-dispatcher-script-creation)

10. [Kernel and Boot Process Manipulation](#kernel-and-boot-process-manipulation)
    - [Kernel Seeking Activity](#kernel-seeking-activity)
    - [Kernel Unpacking Activity](#kernel-unpacking-activity)
    - [Pluggable Authentication Module (PAM) Version Discovery](#pluggable-authentication-module-pam-version-discovery)

11. [Miscellaneous](#miscellaneous)
    - [Kill Command Execution](#kill-command-execution)
    - [Unusual Instance Metadata Service (IMDS) API Request](#unusual-instance-metadata-service-imds-api-request)
    - [Unusual Preload Environment Variable Process Execution](#unusual-preload-environment-variable-process-execution)
    - [Potential OpenSSH Backdoor Logging Activity](#potential-openssh-backdoor-logging-activity)

---

## SSH and Container Security

### SSH Connection Established Inside A Running Container

**Rule ID**: f5488ac1-099e-4008-a6cb-fb638a0f0828

**Description**: This rule detects an incoming SSH connection established inside a running container. Running an SSH daemon inside a container should be avoided and monitored closely if necessary. If an attacker gains valid credentials, they can use it to gain initial access or establish persistence within a compromised environment.

**MITRE Tactics**: Initial Access, Lateral Movement

**MITRE Techniques**: T1021 - Remote Services, T1021.004 - SSH, T1133 - External Remote Services

#### Prerequisites

- Docker installed on the test system
- Root or sudo privileges
- A test container image (we'll use Ubuntu for this example)

#### Test Procedure

1. **Create a test container with SSH server installed**

```bash
# Create a directory for our test
mkdir -p ~/container-ssh-test
cd ~/container-ssh-test

# Create a Dockerfile that includes SSH server
cat > Dockerfile << 'EOF'
FROM ubuntu:20.04

# Install SSH server and required packages
RUN apt-get update && \
    apt-get install -y openssh-server sudo && \
    mkdir /var/run/sshd && \
    echo 'root:password' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Expose SSH port
EXPOSE 22

# Command to run when container starts
CMD ["/usr/sbin/sshd", "-D"]
EOF

# Build the Docker image
docker build -t ssh-test-container .
```

2. **Run the container**

```bash
# Run the container in detached mode
docker run -d --name ssh-test -p 2222:22 ssh-test-container
```

3. **Connect to the container via SSH to trigger the detection rule**

```bash
# First, get the container ID
CONTAINER_ID=$(docker ps -q -f name=ssh-test)
echo "Container ID: $CONTAINER_ID"

# Connect to the container via SSH
# This will trigger the detection rule
ssh -p 2222 root@localhost
# Enter 'password' when prompted
```

4. **Verify the detection**

The rule will detect this activity because:
- The SSH daemon (`sshd`) is running inside a container (container.id is not null)
- The process is the initial process run in a container or start of a new session
- The process is interactive

#### Cleanup

```bash
# Exit the SSH session
exit

# Stop and remove the container
docker stop ssh-test
docker rm ssh-test

# Remove the test image
docker rmi ssh-test-container

# Clean up the test directory
cd ~
rm -rf ~/container-ssh-test
```

#### Warning

This test involves setting up a container with a weak root password. Ensure this is performed in an isolated test environment and not on a production system. The container is also exposed on port 2222 of the host, which could be a security risk if your host is accessible from untrusted networks.

---

### SSH Process Launched From Inside A Container

**Rule ID**: 03a514d9-500e-443e-b6a9-72718c548f6c

**Description**: This rule detects an SSH or SSHD process executed from inside a container. This includes both the client SSH binary and server SSH daemon process. SSH usage inside a container should be avoided and monitored closely when necessary. With valid credentials, an attacker may move laterally to other containers or to the underlying host through container breakout. They may also use valid SSH credentials as a persistence mechanism.

**MITRE Tactics**: Lateral Movement, Persistence

**MITRE Techniques**: T1021 - Remote Services, T1021.004 - SSH, T1133 - External Remote Services

#### Prerequisites

- Docker installed on the test system
- Root or sudo privileges
- A test container image (we'll use Ubuntu for this example)

#### Test Procedure

1. **Create a test container with SSH client installed**

```bash
# Create a directory for our test
mkdir -p ~/container-ssh-process-test
cd ~/container-ssh-process-test

# Create a Dockerfile that includes SSH client
cat > Dockerfile << 'EOF'
FROM ubuntu:20.04

# Install SSH client
RUN apt-get update && \
    apt-get install -y openssh-client

# Command to run when container starts
CMD ["sleep", "infinity"]
EOF

# Build the Docker image
docker build -t ssh-process-test-container .
```

2. **Run the container**

```bash
# Run the container in detached mode
docker run -d --name ssh-process-test ssh-process-test-container
```

3. **Launch SSH process inside the container to trigger the detection rule**

```bash
# First, get the container ID
CONTAINER_ID=$(docker ps -q -f name=ssh-process-test)
echo "Container ID: $CONTAINER_ID"

# Execute the SSH client inside the container
# This will trigger the detection rule even though the connection will fail
docker exec $CONTAINER_ID ssh localhost
```

4. **Alternatively, start the SSH daemon inside the container**

```bash
# Install SSH server inside the running container
docker exec $CONTAINER_ID apt-get update
docker exec $CONTAINER_ID apt-get install -y openssh-server

# Start the SSH daemon inside the container
docker exec $CONTAINER_ID mkdir -p /var/run/sshd
docker exec $CONTAINER_ID /usr/sbin/sshd
```

5. **Verify the detection**

The rule will detect this activity because:
- An SSH process (ssh, sshd, or autossh) is being executed
- The activity is occurring inside a container (container.id is not null)
- The event type is "start" and the action is "fork" or "exec"

#### Cleanup

```bash
# Stop and remove the container
docker stop ssh-process-test
docker rm ssh-process-test

# Remove the test image
docker rmi ssh-process-test-container

# Clean up the test directory
cd ~
rm -rf ~/container-ssh-process-test
```

#### Warning

This test involves installing and running SSH services inside a container, which is generally considered a security risk in production environments. Ensure this is performed in an isolated test environment and not on a production system.

---

### SSH Authorized Keys File Modified Inside a Container

**Rule ID**: f7769104-e8f9-4931-94a2-68fc04eadec3

**Description**: This rule detects the creation or modification of an authorized_keys or sshd_config file inside a container. The Secure Shell (SSH) authorized_keys file specifies which users are allowed to log into a server using public key authentication. Adversaries may modify it to maintain persistence on a victim host by adding their own public key(s). Unexpected and unauthorized SSH usage inside a container can be an indicator of compromise and should be investigated.

**MITRE Tactics**: Lateral Movement, Persistence

**MITRE Techniques**: T1021 - Remote Services, T1021.004 - SSH, T1098 - Account Manipulation, T1098.004 - SSH Authorized Keys, T1563 - Remote Service Session Hijacking, T1563.001 - SSH Hijacking

#### Prerequisites

- Docker installed on the test system
- Root or sudo privileges
- A test container image (we'll use Ubuntu for this example)

#### Test Procedure

1. **Create a test container with SSH server installed**

```bash
# Create a directory for our test
mkdir -p ~/container-ssh-keys-test
cd ~/container-ssh-keys-test

# Create a Dockerfile that includes SSH server
cat > Dockerfile << 'EOF'
FROM ubuntu:20.04

# Install SSH server and required packages
RUN apt-get update && \
    apt-get install -y openssh-server sudo && \
    mkdir -p /var/run/sshd && \
    mkdir -p /root/.ssh

# Expose SSH port
EXPOSE 22

# Command to run when container starts
CMD ["sleep", "infinity"]
EOF

# Build the Docker image
docker build -t ssh-keys-test-container .
```

2. **Run the container**

```bash
# Run the container in detached mode
docker run -d --name ssh-keys-test ssh-keys-test-container
```

3. **Modify the authorized_keys file inside the container to trigger the detection rule**

```bash
# First, get the container ID
CONTAINER_ID=$(docker ps -q -f name=ssh-keys-test)
echo "Container ID: $CONTAINER_ID"

# Execute a command to create an authorized_keys file inside the container
docker exec $CONTAINER_ID bash -c "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0pA4vzQG68HuNSMAJiR7hxUVKMmD1hOr4FxLKGpUUJCn6FtMn+xJHV2QrEMgzLvuRQcKAyWQGxRQCdE7QvGMn6Jx5j0SRsHQvO7Yc9B1lCZjvzQcGVrFTz9oQRnNxY5gKiDIVlD3sK9GQRqrJ+zmQI6BO4bxwYxSQNxn2uYzKDNkTavjzVZnp2RfCu82P4/kUNF7TcgZWkYrWUNXHfLQF6/NKOFGCnVU0b6P7iqmOsLlJ4MkcxfEIEqZZ9ZWsJGz9TF2dKxFsHLcxnJlZBGtcjgbu2ylFdFOQWZJL2x7uyUlMv9D0R9qExH+HfwKe+3xIGD3QZDOvbQwkIzxzfTFp test@example.com' > /root/.ssh/authorized_keys"

# Alternatively, modify the sshd_config file
docker exec $CONTAINER_ID bash -c "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config"
```

4. **Verify the detection**

The rule will detect this activity because:
- A file named "authorized_keys" or "sshd_config" is being created or modified
- The activity is occurring inside a container (container.id is not null)

#### Cleanup

```bash
# Stop and remove the container
docker stop ssh-keys-test
docker rm ssh-keys-test

# Remove the test image
docker rmi ssh-keys-test-container

# Clean up the test directory
cd ~
rm -rf ~/container-ssh-keys-test
```

#### Warning

This test involves creating SSH configuration files that would allow root login and adding an SSH key to the authorized_keys file. In a real environment, this could lead to unauthorized access. Ensure this is performed in an isolated test environment and not on a production system.

---

### Potential Execution via XZBackdoor

**Rule ID**: 7afc6cc9-8800-4c7f-be6b-b688d2dea248

**Description**: This rule identifies potential malicious shell executions through remote SSH and detects cases where the sshd service suddenly terminates soon after successful execution, suggesting suspicious behavior similar to the XZ backdoor.

**MITRE Tactics**: Credential Access, Lateral Movement, Persistence

**MITRE Techniques**: T1021 - Remote Services, T1021.004 - SSH, T1543 - Create or Modify System Process, T1556 - Modify Authentication Process, T1563 - Remote Service Session Hijacking, T1563.001 - SSH Hijacking

#### Prerequisites

- Linux VM with SSH server installed
- Root or sudo privileges
- Two separate systems (one to simulate the attacker, one as the victim)

#### Test Procedure

This rule detects a specific sequence of events that might indicate the XZ backdoor. Testing this rule requires simulating the behavior of the backdoor without actually installing malicious software.

1. **Set up the test environment on the victim system**

```bash
# Create a test script that will simulate the backdoor behavior
cat > /tmp/simulate_xz_backdoor.sh << 'EOF'
#!/bin/bash

# Start sshd with specific arguments
sudo /usr/sbin/sshd -D -R &
SSHD_PID=$!
echo "Started sshd with PID: $SSHD_PID"

# Sleep briefly to simulate the connection being established
sleep 2

# Execute a non-standard command as if it were executed by the sshd process
# This simulates the backdoor executing a command
echo "Executing command as child of sshd"
sudo bash -c "echo 'This is a simulated backdoor command' > /tmp/backdoor_output.txt"

# Terminate sshd with a non-zero exit code
echo "Terminating sshd"
sudo kill -9 $SSHD_PID

# Simulate network disconnect
echo "Simulating network disconnect"
EOF

# Make the script executable
chmod +x /tmp/simulate_xz_backdoor.sh
```

2. **Run the simulation script**

```bash
# Execute the simulation script
sudo /tmp/simulate_xz_backdoor.sh
```

3. **Verify the detection**

The rule will detect this activity because it observes the sequence of:
- An sshd process starting with specific arguments
- A non-standard process being executed as a child of sshd
- The sshd process terminating with a non-zero exit code
- A network disconnect event

#### Cleanup

```bash
# Remove the simulation script and output file
rm /tmp/simulate_xz_backdoor.sh
rm /tmp/backdoor_output.txt

# Ensure the SSH service is properly running
sudo systemctl restart ssh
```

#### Warning

This test involves manipulating the SSH daemon process, which could temporarily disrupt SSH services on the system. Ensure this is performed in an isolated test environment and not on a production system. The test also requires root privileges to start and stop the SSH daemon.

---

### Potential SSH Brute Force Detected on Privileged Account

**Rule ID**: a5f0d057-d540-44f5-924d-c6a2ae92f045

**Description**: This rule identifies multiple consecutive login failures targeting a root user account from the same source address and within a short time interval. Adversaries will often brute force login attempts on privileged accounts with a common or known password, in an attempt to gain privileged access to systems.

**MITRE Tactics**: Credential Access, Lateral Movement

**MITRE Techniques**: T1021 - Remote Services, T1021.004 - SSH, T1110 - Brute Force, T1110.001 - Password Guessing, T1110.003 - Password Spraying

#### Prerequisites

- Linux VM with SSH server installed
- Root or sudo privileges
- SSH client

#### Test Procedure

1. **Ensure SSH server is running and properly configured**

```bash
# Check SSH server status
sudo systemctl status ssh

# If not running, start it
sudo systemctl start ssh

# Ensure password authentication is enabled in SSH config
sudo grep "PasswordAuthentication" /etc/ssh/sshd_config

# If needed, enable password authentication
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

2. **Create a script to simulate brute force attempts**

```bash
# Create a script to attempt multiple failed logins
cat > /tmp/simulate_brute_force.sh << 'EOF'
#!/bin/bash

# Number of attempts
ATTEMPTS=5

# Target username (root or admin)
USERNAME="root"

# Target host (localhost)
HOST="localhost"

echo "Starting simulated brute force attack against $USERNAME@$HOST"
echo "This will attempt $ATTEMPTS failed logins"

for i in $(seq 1 $ATTEMPTS); do
    echo "Attempt $i of $ATTEMPTS"
    # Use a deliberately wrong password
    sshpass -p "wrongpassword$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 $USERNAME@$HOST echo "This should fail"
    # Small delay between attempts
    sleep 1
done

echo "Simulation complete"
EOF

# Make the script executable
chmod +x /tmp/simulate_brute_force.sh
```

3. **Install sshpass if not already installed**

```bash
# Install sshpass (used for automated password entry)
sudo apt-get update
sudo apt-get install -y sshpass
```

4. **Run the brute force simulation script**

```bash
# Execute the simulation script
/tmp/simulate_brute_force.sh
```

5. **Verify the detection**

The rule will detect this activity because:
- Multiple consecutive failed login attempts are made
- The attempts target a privileged account (root or admin)
- The attempts come from the same source IP address
- The attempts occur within a short time interval (10 seconds)

#### Cleanup

```bash
# Remove the simulation script
rm /tmp/simulate_brute_force.sh

# Optionally, restore original SSH configuration
# sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
# sudo systemctl restart ssh
```

#### Warning

This test involves multiple failed login attempts for privileged accounts, which may trigger security alerts or account lockouts depending on your system's security policies. Ensure this is performed in an isolated test environment and not on a production system.

---

### SSH Authorized Keys File Modification

**Rule ID**: 2215b8bd-1759-4ffa-8ab8-55c8e6b32e7f

**Description**: The Secure Shell (SSH) authorized_keys file specifies which users are allowed to log into a server using public key authentication. Adversaries may modify it to maintain persistence on a victim host by adding their own public key(s).

**MITRE Tactics**: Lateral Movement, Persistence

**MITRE Techniques**: T1021 - Remote Services, T1021.004 - SSH, T1098 - Account Manipulation, T1098.004 - SSH Authorized Keys, T1563 - Remote Service Session Hijacking, T1563.001 - SSH Hijacking

#### Prerequisites

- Linux VM with SSH server installed
- User account with a home directory

#### Test Procedure

1. **Create a test SSH key pair**

```bash
# Create a directory for our test
mkdir -p ~/ssh-keys-test
cd ~/ssh-keys-test

# Generate a test SSH key pair
ssh-keygen -t rsa -b 2048 -f ./test_key -N ""
```

2. **Create or modify the authorized_keys file**

```bash
# Create .ssh directory if it doesn't exist
mkdir -p ~/.ssh

# Add the test public key to the authorized_keys file
cat test_key.pub >> ~/.ssh/authorized_keys

# Alternatively, modify the sshd_config file (requires root)
# sudo bash -c "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config"
```

3. **Verify the detection**

The rule will detect this activity because:
- A file named "authorized_keys" or "authorized_keys2" or "/etc/ssh/sshd_config" is being created or modified
- The process is not in the exclusion list (git, maven, java, vim, etc.)

#### Cleanup

```bash
# Remove the test key from authorized_keys
grep -v "$(cat test_key.pub)" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.new
mv ~/.ssh/authorized_keys.new ~/.ssh/authorized_keys

# Remove the test files
cd ~
rm -rf ~/ssh-keys-test
```

#### Warning

This test involves modifying SSH configuration files that control access to your system. Ensure this is performed in an isolated test environment and not on a production system. Be careful not to remove legitimate keys from your authorized_keys file during cleanup.

---

### SSH Key Generated via ssh-keygen

**Rule ID**: 7df3cb8b-5c0c-4228-b772-bb6cd619053c

**Description**: This rule identifies the creation of SSH keys using the ssh-keygen tool, which is the standard utility for generating SSH keys. Users often create SSH keys for authentication with remote services. However, threat actors can exploit this tool to move laterally across a network or maintain persistence by generating unauthorized SSH keys, granting them SSH access to systems.

**MITRE Tactics**: Lateral Movement, Persistence

**MITRE Techniques**: T1021 - Remote Services, T1021.004 - SSH, T1098 - Account Manipulation, T1098.004 - SSH Authorized Keys, T1563 - Remote Service Session Hijacking, T1563.001 - SSH Hijacking

#### Prerequisites

- Linux VM with SSH client installed
- User account with a home directory

#### Test Procedure

1. **Generate an SSH key pair**

```bash
# Create a directory for our test
mkdir -p ~/ssh-keygen-test
cd ~/ssh-keygen-test

# Generate a test SSH key pair
ssh-keygen -t rsa -b 2048 -f ~/.ssh/test_key -N ""
```

2. **Verify the detection**

The rule will detect this activity because:
- A file is created in the ~/.ssh/ directory
- The process that created the file is /usr/bin/ssh-keygen
- The file is not a known_hosts file

#### Cleanup

```bash
# Remove the generated SSH key pair
rm -f ~/.ssh/test_key
rm -f ~/.ssh/test_key.pub

# Remove the test directory
cd ~
rm -rf ~/ssh-keygen-test
```

#### Warning

This test involves creating SSH keys that could potentially be used for authentication. Ensure this is performed in an isolated test environment and not on a production system. Be careful to remove all test keys after the test is complete.

---

### Network Connection from SSH Daemon Child Process

**Rule ID**: 63431796-f813-43af-820b-492ee2efec8e

**Description**: This rule identifies an egress internet connection initiated by an SSH Daemon child process. This behavior is indicative of the alteration of a shell configuration file or other mechanism that launches a process when a new SSH login occurs. Attackers can also backdoor the SSH daemon to allow for persistence, call out to a C2 or to steal credentials.

**MITRE Tactics**: Command and Control, Lateral Movement, Persistence

**MITRE Techniques**: T1021 - Remote Services, T1021.004 - SSH, T1546 - Event Triggered Execution, T1546.004 - Unix Shell Configuration Modification, T1563 - Remote Service Session Hijacking, T1563.001 - SSH Hijacking

#### Prerequisites

- Linux VM with SSH server installed
- Root or sudo privileges
- SSH client

#### Test Procedure

1. **Create a test script that will initiate a network connection**

```bash
# Create a directory for our test
mkdir -p ~/ssh-network-test
cd ~/ssh-network-test

# Create a script that will make a network connection
cat > network_test.sh << 'EOF'
#!/bin/bash

# Make a simple HTTP request to a public website
curl -s http://example.com > /dev/null

# Log the activity for verification
echo "Network connection made at $(date)" >> ~/ssh-network-test/network_log.txt
EOF

# Make the script executable
chmod +x network_test.sh
```

2. **Modify the SSH configuration to run the script on login**

```bash
# Create a temporary SSH configuration file
cat > /tmp/sshrc << 'EOF'
#!/bin/bash

# Run our network test script
~/ssh-network-test/network_test.sh &
EOF

# Make the file executable
chmod +x /tmp/sshrc

# Copy it to the system-wide SSH directory (requires root)
sudo cp /tmp/sshrc /etc/ssh/sshrc
```

3. **Connect via SSH to trigger the detection rule**

```bash
# Connect to localhost via SSH
# This will trigger the script to run and make a network connection
ssh localhost
```

4. **Verify the detection**

The rule will detect this activity because:
- A process whose parent is the SSH daemon makes a network connection
- The connection is to a non-private IP address
- The process is not in the exclusion list (yum, dnf, etc.)

#### Cleanup

```bash
# Remove the SSH configuration file
sudo rm /etc/ssh/sshrc

# Remove the test files
cd ~
rm -rf ~/ssh-network-test
rm /tmp/sshrc
```

#### Warning

This test involves modifying SSH configuration files that affect how the SSH daemon behaves when users log in. Ensure this is performe
