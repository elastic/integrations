sleep 10

while :
do
    curl -u admin:admin -d "body=message" http://localhost:8161/api/message/TEST?type=queue
    sleep 1  
done

