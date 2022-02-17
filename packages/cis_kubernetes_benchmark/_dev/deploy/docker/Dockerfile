FROM ipfs/go-ipfs@sha256:f7e30972e35a839ea8ce00c060412face29aa31624fd2dc87a5e696f99835a91

RUN mkdir -p /var/log/ipfs

ADD docker-entrypoint.sh /

ENV IPFS_LOGGING "info"

ENTRYPOINT ["/docker-entrypoint.sh"]