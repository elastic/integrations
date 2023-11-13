#/bin/bash

# 1. Required dependencies
sudo apt-get update
sudo apt-get -y install apt-transport-https ca-certificates curl gnupg lsb-release

# 2. GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# 3. Use stable repository for Docker
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 4. Install Docker
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io

# 5. Add user to docker group
sudo groupadd docker
sudo usermod -aG docker $USER
sudo update-alternatives --config iptables

sudo service docker start   # start the engine
sudo service docker status
docker run hello-world