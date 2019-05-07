FROM bepsays/ci-goreleaser:1.12-2

RUN apt-get -y update \
    && apt-get -y install vim rpm reprepro createrepo \
    && wget https://dl.bintray.com/homebrew/mirror/berkeley-db-18.1.32.tar.gz \

    # Berkeley DB
    && tar zxvf berkeley-db-18.1.32.tar.gz \
    && cd db-18.1.32/build_unix \

    # Linux
    && ../dist/configure --prefix=/usr/local --host=x86_64-linux \
    && make \
    && make install \

    # Darwin
    && make clean \
    && ../dist/configure --prefix=/usr/local --host=x86_64-apple-darwin15 \
    && make \
    && make install
