FROM alpine:3.15.0
RUN apk --no-cache add ca-certificates git expat==2.4.4-r0
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
