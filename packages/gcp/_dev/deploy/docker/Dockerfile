FROM google/cloud-sdk

RUN apt-get install python3 python3-pip

RUN pip3 install virtualenv

COPY ./scripts /scripts

RUN chmod +x /scripts/entrypoint.sh

WORKDIR /scripts/python-pubsub

COPY ./logs /sample_logs

RUN virtualenv env
RUN . env/bin/activate

RUN pip3 install -r requirements.txt

EXPOSE 8538

ENTRYPOINT [ "/scripts/entrypoint.sh" ]
