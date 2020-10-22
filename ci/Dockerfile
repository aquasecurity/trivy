FROM circleci/golang:1.15-buster

RUN sudo apt-get -y update \
    && sudo apt-get -y install rpm reprepro createrepo distro-info

ARG GORELEASER_VERSION=0.124.1
ARG GORELEASER_ARTIFACT=goreleaser_Linux_x86_64.tar.gz
RUN wget https://github.com/goreleaser/goreleaser/releases/download/v${GORELEASER_VERSION}/${GORELEASER_ARTIFACT} \
    && sudo tar -xzf ${GORELEASER_ARTIFACT} -C /usr/bin/ goreleaser \
    && rm ${GORELEASER_ARTIFACT}
