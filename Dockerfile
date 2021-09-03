FROM alpine:3.12
RUN apk --no-cache add ca-certificates=20191127-r4 git=2.26.3-r0 rpm=4.15.1-r2
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
