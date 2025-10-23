#!/bin/sh
set -e

# Set environment variables for Azure cli
export AZURE_STORAGE_ACCOUNT=devstoreaccount1
export AZURE_STORAGE_KEY="Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=http;AccountName=$AZURE_STORAGE_ACCOUNT;AccountKey=$AZURE_STORAGE_KEY;BlobEndpoint=http://127.0.0.1:10000/$AZURE_STORAGE_ACCOUNT;"

# Start Azurite in background
azurite-blob --blobHost 0.0.0.0 --blobPort 10000 --skipApiVersionCheck &
AZURITE_PID=$!

# Wait until Azurite is ready
while ! nc -z 127.0.0.1 10000; do sleep 0.5; done

# Create container
az storage container create --name test-container

# Upload all files
for f in /sample_logs/*; do
  if [ -f "$f" ]; then
    az storage blob upload --container-name test-container --file "$f" --name "$(basename "$f")"
  fi
done

node -e "
const http = require('http');
const server = http.createServer((req, res) => { res.writeHead(200); res.end('OK'); });
server.listen(4443, () => console.log('Healthcheck API available on port 4443'));
" &

echo "All files uploaded. Healthcheck API started."

# Keep Azurite running
wait $AZURITE_PID
