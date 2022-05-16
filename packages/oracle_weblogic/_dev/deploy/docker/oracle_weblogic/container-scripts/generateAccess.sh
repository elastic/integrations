#!/bin/bash
while true
do
    curl http://localhost:7001/sample/ > curl.log
    sleep 1
done