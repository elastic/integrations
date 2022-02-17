#!/bin/sh

/usr/local/bin/start_ipfs daemon --migrate=true | tee /var/log/ipfs/ipfs-node-0.log