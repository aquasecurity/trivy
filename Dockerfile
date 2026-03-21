FROM alpine:3.23.3
RUN addgroup -g 1000 -S appgroup && adduser -u 1000 -S appuser -G appgroup
RUN apk --no-cache add ca-certificates git
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/

RUN mkdir /reports
RUN chown -R appuser:appgroup /reports

USER appuser
ENTRYPOINT ["trivy"]
