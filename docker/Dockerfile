FROM alpine:latest
MAINTAINER Jon Hadfield <jon@lessknown.co.uk>
RUN apk add --update --no-cache ca-certificates bash && rm -f /var/cache/apk/*
ADD ape_linux_amd64 ape
ENTRYPOINT ["/bin/bash", "-c", "/ape \"$@\"", "--"]