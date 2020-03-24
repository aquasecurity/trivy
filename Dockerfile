FROM alpine:3.11
RUN apk --no-cache add ca-certificates git rpm
COPY trivy /usr/local/bin/trivy
COPY contrib/gitlab.tpl contrib/gitlab.tpl
ENTRYPOINT ["trivy"]
