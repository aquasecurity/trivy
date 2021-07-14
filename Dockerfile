FROM alpine:3.13
RUN apk --no-cache add ca-certificates==20191127-r5 git==2.30.2-r0
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
