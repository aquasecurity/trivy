FROM alpine:3.24.2
# CVE-2026-85091: remove after alpine base ships zlib >= 1.3.2-r1
RUN apk --no-cache add ca-certificates git 'zlib>=1.3.2-r1'
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
