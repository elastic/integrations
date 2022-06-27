mkdir logs
cp /sample_logs/* /opt/apache-activemq-5.17.1/logs/
chmod a+rw -R /opt/apache-activemq-5.17.1/logs/
sleep 10

while :
do
    curl -u admin:admin -d "body=message" http://localhost:8161/api/message/TEST?type=queue
    sleep 1  
done

