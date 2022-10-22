FROM alpine:latest

RUN addgroup -g 1000 acme && adduser acme -D -H -u 1000 -G acme && \
    apk --no-cache add coreutils bash acme.sh && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x ./kubectl && \
    mv ./kubectl /usr/local/bin/kubectl && \
    acme.sh --version && kubectl version --client && \
    mkdir /data && chown acme:acme /data
COPY ./main.sh /main.sh
ARG GIT_COMMIT_SHA
ARG BUILD_TIMESTAMP
ENV GIT_COMMIT_SHA=$GIT_COMMIT_SHA BUILD_TIMESTAMP=$BUILD_TIMESTAMP
USER acme
ENTRYPOINT [ "/main.sh" ]