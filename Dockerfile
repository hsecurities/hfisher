FROM alpine:latest
LABEL MAINTAINER="https://github.com/hsecurities/hfisher"
WORKDIR /hfisher/
ADD . /hfisher
RUN apk add --no-cache bash ncurses curl unzip wget php 
CMD "./hfisher.sh"
