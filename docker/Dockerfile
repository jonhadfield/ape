FROM alpine:latest
MAINTAINER Jon Hadfield <jon@lessknown.co.uk>
RUN apk add --update ca-certificates bash
ADD ape_linux_amd64 ape
ENTRYPOINT ["/bin/bash", "-c", "/ape \"$@\"", "--"]