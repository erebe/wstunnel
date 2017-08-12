FROM alpine:latest
MAINTAINER github@erebe.eu


RUN adduser -D wstunnel
ADD https://github.com/erebe/wstunnel/blob/master/bin/wstunnel_x86_64?raw=true /home/wstunnel/wstunnel
RUN chmod +x /home/wstunnel/wstunnel

EXPOSE 8080
USER wstunnel

ENTRYPOINT ["/home/wstunnel/wstunnel"]

