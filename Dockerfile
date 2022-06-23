FROM alpine:3.15.0
RUN apk --no-cache add ca-certificates git bash curl wget
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN wget http://alpine.adiscon.com/rsyslog@lists.adiscon.com-5a55e598.rsa.pub
RUN echo 'http://alpine.adiscon.com/3.7/stable' >> /etc/apk/repositories
#RUN apk update
RUN apk add rsyslog \
  && rm -rf /var/cache/apk/*

ADD rsyslog.conf /etc/rsyslog.conf

#COPY trivy /usr/local/bin/trivy
#COPY contrib/*.tpl contrib/
CMD ["/bin/bash"]
#ENTRYPOINT [ "rsyslogd", "-n" ]
