FROM alpine:3.22.1
RUN apk --no-cache add ca-certificates git catatonit
COPY trivy /usr/local/bin/
COPY contrib/*.tpl contrib/
ENTRYPOINT ["catatonit", "--", "trivy"]
