FROM node:20-bullseye-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    netcat \
    ca-certificates \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*
# Install Azurite
RUN npm install -g azurite

# Install Azure CLI
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Copy emulator script
COPY files/emulator.sh /emulator.sh
RUN chmod +x /emulator.sh

ENTRYPOINT ["/bin/sh", "/emulator.sh"]
