FROM alpine:3.16.2
RUN apk --no-cache add ca-certificates git && \ 
    adduser -g "trivy" trivy
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
USER trivy
ENTRYPOINT ["trivy"]
