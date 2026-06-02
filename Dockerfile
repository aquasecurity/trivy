FROM alpine:3.23.4
RUN apk --no-cache add ca-certificates git
# Default "." supports local builds; dockers_v2 sets this to e.g. linux/amd64
ARG TARGETPLATFORM=.
COPY ${TARGETPLATFORM}/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
