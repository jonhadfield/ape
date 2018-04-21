FROM alpine:latest
MAINTAINER Jon Hadfield <jon@lessknown.co.uk>
RUN apk add --update --no-cache ca-certificates bash curl && rm -f /var/cache/apk/*
RUN curl -L https://dl.bintray.com/jonhadfield/ape/ape_linux_amd64 -o /ape \
    && chmod 755 /ape
ENTRYPOINT ["/bin/bash", "-c", "/ape \"$@\"", "--"]