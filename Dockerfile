FROM alpine:latest

RUN addgroup -g 1000 acme && adduser acme -D -H -u 1000 -G acme && \
    apk --no-cache add coreutils bash acme.sh && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x ./kubectl && \
    mv ./kubectl /usr/local/bin/kubectl && \
    acme.sh --version && kubectl version --client 

COPY ./main.sh /main.sh

USER acme
ENTRYPOINT [ "/main.sh" ]