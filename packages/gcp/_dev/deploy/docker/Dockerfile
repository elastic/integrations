FROM golang:1.15 AS build
WORKDIR /src
COPY ./publisher .
RUN go build -o /out/publisher .

FROM debian:stretch AS run
ARG SDK_VERSION

RUN \
    apt-get update \
	&& apt-get install -y \
	    apt-transport-https \
	    ca-certificates \
	    curl \
		python \
		openjdk-8-jre \
		gnupg2 \
	&& rm -rf /var/lib/apt/lists/*

RUN \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
        >> /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg \
        | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -

RUN \
    apt-get update \
    && apt-get install -y \
        google-cloud-sdk=${SDK_VERSION} \
        google-cloud-sdk-pubsub-emulator=${SDK_VERSION} \
	&& rm -rf /var/lib/apt/lists/*

RUN \
    mkdir /data

COPY --from=build /out/publisher /
COPY ./entrypoint.sh .
RUN chmod u+x ./entrypoint.sh
COPY ./sample_logs /sample_logs

# HEALTHCHECK --interval=1s --retries=90 CMD curl -s -f http://localhost:8432/

ENTRYPOINT [ "./entrypoint.sh" ]
