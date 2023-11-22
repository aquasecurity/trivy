FROM ubuntu:18.04
RUN apt-get update && apt-get install -y --no-install-recommends mysql-client     && rm -rf /var/lib/apt/lists/* && apt-get clean
USER mike
ENTRYPOINT mysql