FROM alpine:3.12
RUN addgroup -g 1000 -S appgroup && adduser -u 1000 -S appuser -G appgroup
RUN apk --no-cache add ca-certificates git rpm
COPY trivy /usr/local/bin/trivy
COPY contrib/gitlab.tpl contrib/gitlab.tpl
COPY contrib/junit.tpl contrib/junit.tpl
USER appuser
ENTRYPOINT ["trivy"]
