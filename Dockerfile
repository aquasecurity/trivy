FROM alpine:3.24.3
# The Alpine base image tag lags behind security fixes in its repository,
# so upgrade preinstalled packages to the latest patched versions.
RUN apk --no-cache upgrade && apk --no-cache add ca-certificates git
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
