FROM alpine:3.16.2
RUN apk --no-cache add ca-certificates git
RUN apk add --upgrade expat-dev
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
