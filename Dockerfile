FROM alpine:3.15.0
RUN apk --no-cache add ca-certificates git bash curl
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
#COPY trivy /usr/local/bin/trivy
#COPY contrib/*.tpl contrib/
CMD ["/bin/bash"]
#ENTRYPOINT ["trivy"]
