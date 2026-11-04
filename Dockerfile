FROM alpine:3.24.3
RUN apk --no-cache add ca-certificates git
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
