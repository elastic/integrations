# Whenever docker container is ran it will remove log files from SERVICE_LOGS_DIR, so to make them accessible again for the docker container to run system test,
# following commands will help to copy and accesses these files from SERVICE_LOGS_DIR again. 
mkdir logs
cp /sample_logs/* /opt/apache-activemq-5.17.1/logs/ 
chmod a+rw -R /opt/apache-activemq-5.17.1/logs/ 
sleep 10

while :
do
    curl -u admin:admin -d "body=message" http://localhost:8161/api/message/TEST?type=queue
    sleep 1  
done

