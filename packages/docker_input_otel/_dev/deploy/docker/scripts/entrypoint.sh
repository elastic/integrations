#!/bin/sh
set -e

echo "Check binaries..."
which docker && which sh
echo "Waiting for Docker daemon at $DOCKER_HOST..."
# Simply wait for the daemon
while ! docker info >/dev/null 2>&1; do
  echo "Waiting for Docker daemon connection..."
  sleep 5
done
echo "Docker daemon found!"
docker info

docker_image="alpine"
container_name="stressful"

# Start a container that generates some stats (simulating load)
echo "Starting $container_name container..."
# Identify if container already exists to avoid conflict on restart
docker rm -f $container_name || true
# Pull alpine with retries to handle transient registry/network errors (same idea as elastic-package retry)
retries=10
count=0
until docker pull $docker_image; do
  exit=$?
  wait=$((2 ** count))
  count=$((count + 1))
  if [ $count -lt "$retries" ]; then
    echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
    sleep $wait
  else
    echo "Retry $count/$retries exited $exit, no more retries left."
    exit $exit
  fi
done
docker run -d --name $container_name $docker_image sh -c "while true; do sleep 1; echo 'Hello, World!'; done"
echo "$container_name container running."
# Keep this container alive
docker logs -f $container_name
