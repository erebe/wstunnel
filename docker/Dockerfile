FROM alpine:latest
MAINTAINER github@erebe.eu


ADD https://github.com/erebe/wstunnel/blob/master/bin/wstunnel_x86_64?raw=true wstunnel
RUN chmod +x ./wstunnel

ENTRYPOINT ["./wstunnel"]

