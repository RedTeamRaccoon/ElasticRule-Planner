# Red Team Validation Guide for Elastic Detection Rules

This guide provides step-by-step instructions for testing Elastic detection rules in a controlled environment. Each section includes detailed procedures to safely trigger detection rules, allowing security teams to validate their detection capabilities.

## Table of Contents

1. [SSH Brute Force and Backdoor Detection](#ssh-brute-force-and-backdoor-detection)
   - [SSH Connection Established Inside A Running Container (f5488ac1-099e-4008-a6cb-fb638a0f0828)](#ssh-connection-established-inside-a-running-container)
   - [SSH Authorized Keys File Modified Inside a Container (f7769104-e8f9-4931-94a2-68fc04eadec3)](#ssh-authorized-keys-file-modified-inside-a-container)

---

## SSH Brute Force and Backdoor Detection

### SSH Connection Established Inside A Running Container (f5488ac1-099e-4008-a6cb-fb638a0f0828)

This rule detects when an SSH connection is established inside a running container. Running an SSH daemon inside a container is generally considered a security risk and should be avoided in production environments. If an attacker gains valid credentials, they can use SSH to gain initial access or establish persistence within a compromised container environment.

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

### SSH Authorized Keys File Modified Inside a Container (f7769104-e8f9-4931-94a2-68fc04eadec3)

This rule detects the creation or modification of an authorized_keys or sshd_config file inside a container. Attackers may modify these files to maintain persistence by adding their own SSH keys, allowing unauthorized access to the container.

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

## Container Security

### SSH Process Launched From Inside A Container (03a514d9-500e-443e-b6a9-72718c548f6c)

This rule detects when an SSH or SSHD process is executed from inside a container. This includes both the client SSH binary and server SSH daemon process. SSH usage inside containers should generally be avoided as it can be used by attackers to move laterally to other containers or to the underlying host through container breakout.

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
