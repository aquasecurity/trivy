FROM golang:1.7.3 as dep
COPY  /binary /

FROM alpine:3.13
USER mike
ENTRYPOINT [ "/opt/app/run.sh --port 8080" ]