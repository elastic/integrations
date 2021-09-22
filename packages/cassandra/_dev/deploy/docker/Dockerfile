FROM adoptopenjdk:8-jre-hotspot-focal

ENV JOLOKIA_VERSION=1.3.3 JOLOKIA_HOST=0.0.0.0 JOLOKIA_PORT=8778

# explicitly set user/group IDs
RUN set -eux; \
	groupadd -r cassandra --gid=999; \
	useradd -r -g cassandra --uid=999 cassandra

RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
# solves warning: "jemalloc shared library could not be preloaded to speed up memory allocations"
		libjemalloc2 \
# "free" is used by cassandra-env.sh
		procps \
# "cqlsh" needs a python interpreter
		python \
# "ip" is not required by Cassandra itself, but is commonly used in scripting Cassandra's configuration (since it is so fixated on explicit IP addresses)
		iproute2 \
# Cassandra will automatically use numactl if available
#   https://github.com/apache/cassandra/blob/18bcda2d4c2eba7370a0b21f33eed37cb730bbb3/bin/cassandra#L90-L100
#   https://github.com/apache/cassandra/commit/604c0e87dc67fa65f6904ef9a98a029c9f2f865a
		numactl \
	; \
	rm -rf /var/lib/apt/lists/*; \
# https://issues.apache.org/jira/browse/CASSANDRA-15767 ("bin/cassandra" only looks for "libjemalloc.so" or "libjemalloc.so.1" which doesn't match our "libjemalloc.so.2")
	libjemalloc="$(readlink -e /usr/lib/*/libjemalloc.so.2)"; \
	ln -sT "$libjemalloc" /usr/local/lib/libjemalloc.so; \
	ldconfig

# grab gosu for easy step-down from root
# https://github.com/tianon/gosu/releases
ENV GOSU_VERSION 1.12
RUN set -eux; \
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends ca-certificates dirmngr gnupg wget; \
	rm -rf /var/lib/apt/lists/*; \
	dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
	wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
	wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc"; \
	export GNUPGHOME="$(mktemp -d)"; \
	gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
	gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
	gpgconf --kill all; \
	rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc; \
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark > /dev/null; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	chmod +x /usr/local/bin/gosu; \
	gosu --version; \
	gosu nobody true

ENV CASSANDRA_HOME /opt/cassandra
ENV CASSANDRA_CONF /etc/cassandra
ENV PATH $CASSANDRA_HOME/bin:$PATH

# https://cwiki.apache.org/confluence/display/CASSANDRA2/DebianPackaging#DebianPackaging-AddingRepositoryKeys
# $ docker run --rm buildpack-deps:buster-curl bash -c 'wget -qO- https://downloads.apache.org/cassandra/KEYS | gpg --batch --import &> /dev/null && gpg --batch --list-keys --with-fingerprint --with-colons' | awk -F: '$1 == "pub" && $2 == "-" { pub = 1 } pub && $1 == "fpr" { fpr = $10 } $1 == "sub" { pub = 0 } pub && fpr && $1 == "uid" && $2 == "-" { print "#", $10; print "\t" fpr " \\"; pub = 0 }'
ENV GPG_KEYS \
# Eric Evans <eevans@sym-link.com>
	CEC86BB4A0BA9D0F90397CAEF8358FA2F2833C93 \
# Eric Evans <eevans@sym-link.com>
	C4965EE9E3015D192CCCF2B6F758CE318D77295D \
# Sylvain Lebresne (pcmanus) <sylvain@datastax.com>
	5AED1BF378E9A19DADE1BCB34BD736A82B5C1B00 \
# T Jake Luciani <jake@apache.org>
	514A2AD631A57A16DD0047EC749D6EEC0353B12C \
# Michael Shuler <michael@pbandjelly.org>
	A26E528B271F19B9E5D8E19EA278B781FE4B2BDA \
# Michael Semb Wever <mick@thelastpickle.com>
	A4C465FEA0C552561A392A61E91335D77E3E87CB \
# Alex Petrov <oleksandr.petrov@gmail.com>
	9E66CEC6106D578D0B1EB9BFF1000962B7F6840C \
# Jordan West <jwest@apache.org>
	C4009872C59B49561310D966D0062876AF30F054 \
# Brandon Williams <brandonwilliams@apache.org>
	B7842CDAF36E6A3214FAE35D5E85B9AE0B84C041 \
# Ekaterina Buryanova Dimitrova (CODE SIGNING KEY) <e.dimitrova@gmail.com>
	3E9C876907A560ACA00964F363E9BAD215BBF5F0

ENV CASSANDRA_VERSION 3.11.11
ENV CASSANDRA_SHA512 5a7dc4237c9f43526b63cae62f04d73ec60f28e86ee1dd4bd4aaa55d2063d74fe842e015f7f68512db7deadbe52cab37417341183a716c191035463992e42d37

RUN set -eux; \
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends ca-certificates dirmngr gnupg wget; \
	rm -rf /var/lib/apt/lists/*; \
	\
	ddist() { \
		local f="$1"; shift; \
		local distFile="$1"; shift; \
		local success=; \
		local distUrl=; \
		for distUrl in \
# https://issues.apache.org/jira/browse/INFRA-8753?focusedCommentId=14735394#comment-14735394
			'https://www.apache.org/dyn/closer.cgi?action=download&filename=' \
# if the version is outdated (or we're grabbing the .asc file), we might have to pull from the dist/archive :/
			https://www-us.apache.org/dist/ \
			https://www.apache.org/dist/ \
			https://archive.apache.org/dist/ \
		; do \
			if wget --progress=dot:giga -O "$f" "$distUrl$distFile" && [ -s "$f" ]; then \
				success=1; \
				break; \
			fi; \
		done; \
		[ -n "$success" ]; \
	}; \
	\
	ddist 'cassandra-bin.tgz' "cassandra/$CASSANDRA_VERSION/apache-cassandra-$CASSANDRA_VERSION-bin.tar.gz"; \
	echo "$CASSANDRA_SHA512 *cassandra-bin.tgz" | sha512sum --check --strict -; \
	\
	ddist 'cassandra-bin.tgz.asc' "cassandra/$CASSANDRA_VERSION/apache-cassandra-$CASSANDRA_VERSION-bin.tar.gz.asc"; \
	export GNUPGHOME="$(mktemp -d)"; \
	for key in $GPG_KEYS; do \
		gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$key"; \
	done; \
	gpg --batch --verify cassandra-bin.tgz.asc cassandra-bin.tgz; \
	rm -rf "$GNUPGHOME"; \
	\
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark > /dev/null; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	\
	mkdir -p "$CASSANDRA_HOME"; \
	tar --extract --file cassandra-bin.tgz --directory "$CASSANDRA_HOME" --strip-components 1; \
	rm cassandra-bin.tgz*; \
	\
	[ ! -e "$CASSANDRA_CONF" ]; \
	mv "$CASSANDRA_HOME/conf" "$CASSANDRA_CONF"; \
	ln -sT "$CASSANDRA_CONF" "$CASSANDRA_HOME/conf"; \
	\
	dpkgArch="$(dpkg --print-architecture)"; \
	case "$dpkgArch" in \
		ppc64el) \
# https://issues.apache.org/jira/browse/CASSANDRA-13345
# "The stack size specified is too small, Specify at least 328k"
			if grep -q -- '^-Xss' "$CASSANDRA_CONF/jvm.options"; then \
# 3.11+ (jvm.options)
				grep -- '^-Xss256k$' "$CASSANDRA_CONF/jvm.options"; \
				sed -ri 's/^-Xss256k$/-Xss512k/' "$CASSANDRA_CONF/jvm.options"; \
				grep -- '^-Xss512k$' "$CASSANDRA_CONF/jvm.options"; \
			elif grep -q -- '-Xss256k' "$CASSANDRA_CONF/cassandra-env.sh"; then \
# 3.0 (cassandra-env.sh)
				sed -ri 's/-Xss256k/-Xss512k/g' "$CASSANDRA_CONF/cassandra-env.sh"; \
				grep -- '-Xss512k' "$CASSANDRA_CONF/cassandra-env.sh"; \
			fi; \
			;; \
	esac; \
	\
	mkdir -p "$CASSANDRA_CONF" /var/lib/cassandra /var/log/cassandra; \
	chown -R cassandra:cassandra "$CASSANDRA_CONF" /var/lib/cassandra /var/log/cassandra; \
	chmod 777 "$CASSANDRA_CONF" /var/lib/cassandra /var/log/cassandra; \
	chmod -R a+rwX "$CASSANDRA_CONF"; \
	ln -sT /var/lib/cassandra "$CASSANDRA_HOME/data"; \
	ln -sT /var/log/cassandra "$CASSANDRA_HOME/logs"; \
	\
# smoke test
	cassandra -v

RUN cp -f $JAVA_HOME/lib/management/jmxremote.access $JAVA_HOME/lib/management/jmxremote.access.bak \
   &&  chown root:cassandra $JAVA_HOME/lib/management/jmxremote.access* \
   &&  chmod 664 $JAVA_HOME/lib/management/jmxremote.access*

ENV CASSANDRA_LIB=/var/lib/cassandra

RUN set -eux; \
    savedAptMark="$(apt-mark showmanual)"; \
    apt-get update; \
    apt-get install -y --no-install-recommends wget \
    &&  wget http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/${JOLOKIA_VERSION}/jolokia-jvm-${JOLOKIA_VERSION}-agent.jar \
	-O $CASSANDRA_LIB/jolokia-jvm-${JOLOKIA_VERSION}-agent.jar

VOLUME /var/lib/cassandra

ENV JMX_REMOTE=yes JOLOKIA_ENABLED=yes

COPY docker-entrypoint-initdb.d /usr/local/bin/
RUN ln -s usr/local/bin/docker-entrypoint.sh /docker-entrypoint.sh # backwards compat
ENTRYPOINT ["docker-entrypoint.sh"]

# 7000: intra-node communication
# 7001: TLS intra-node communication
# 7199: JMX
# 9042: CQL
# 9160: thrift service
# 8778: jolokia
EXPOSE 7000 7001 7199 9042 9160 8778
CMD ["cassandra", "-f"]