ARG ELASTIC_VERSION

# https://www.docker.elastic.co/
FROM docker.elastic.co/elasticsearch/elasticsearch:${ELASTIC_VERSION:-9.0.3}

USER 0
RUN microdnf install --setopt=tsflags=nodocs -y openssl && \
    microdnf clean all
USER 1000:0

ENTRYPOINT ["/entrypoint.sh"]
