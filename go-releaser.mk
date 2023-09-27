export BINARY_NAME := trivy
export GIT_REPO_NAME := $(strip $(shell basename -s .git `git config --get remote.origin.url`))
export WORKING_DIR := /mnt/$(GIT_REPO_NAME)
export DOCKER_REPO_PATH := 889956758113.dkr.ecr.us-west-2.amazonaws.com
export DOCKER_REPO_NAME := ics/trivy
export DOCKER_REGION := us-west-2
export DOCKER_TAG := local
export LOCAL_BRANCH := $(shell git branch | grep \* | cut -d ' ' -f2)
export BUILD_NUM := local
export DEVBOX_TAG := go1.17.5-java17-linux4.13.0-45-generic-docker20.10.12
export DEVBOX_REPO := 889956758113.dkr.ecr.us-west-2.amazonaws.com/tools/devbox
export LAST_COMMIT := $(shell git rev-parse --short HEAD)
export CHECKOUT_TMP_FOLDER := /tmp/jenkins-divvy-shared-libraries-tmp
export DEVBOX_HOME := /home/devbox
export BUILD_TOOLS_LIBRARY := git@github.com:rapid7/jenkins-divvy-shared-libraries

#Jenkins builds pass that
ifneq ($(DOCKER_REPO_PATH_JEN),)
	DOCKER_REPO_PATH = $(DOCKER_REPO_PATH_JEN)
endif

ifneq ($(DOCKER_REPO_NAME_JEN),)
	DOCKER_REPO_NAME = $(DOCKER_REPO_NAME_JEN)
endif

ifneq ($(DOCKER_REGION_JEN),)
	DOCKER_REGION = $(DOCKER_REGION_JEN)
endif

ifneq ($(DOCKER_TAG_JEN),)
	DOCKER_TAG = $(DOCKER_TAG_JEN)
endif

ifneq ($(LOCAL_BRANCH_JEN),)
	LOCAL_BRANCH = $(LOCAL_BRANCH_JEN)
endif

ifneq ($(GITHUB_APP),)
	BUILD_TOOLS_LIBRARY =  https://$(GITHUB_APP):$(GITHUB_TOKEN)@github.com/rapid7/jenkins-divvy-shared-libraries.git
endif


.PHONY: goreleaser


.PHONY: shell
shell:
	docker run -it -v ${PWD}:${WORKING_DIR} -w ${WORKING_DIR} golang:1.17

configure-env:
	rm -rf ${CHECKOUT_TMP_FOLDER}
	git clone ${BUILD_TOOLS_LIBRARY} ${CHECKOUT_TMP_FOLDER} --depth 1
	cp ${CHECKOUT_TMP_FOLDER}/resources/scripts/goreleaser ./
	cp ${CHECKOUT_TMP_FOLDER}/resources/scripts/docker_auth.sh ./
	chmod 755 ./goreleaser
	chmod 755 ./docker_auth.sh

docker_auth: configure-env
	cat docker_auth.sh | \
	bash -s ${DOCKER_REPO_PATH} ${DOCKER_REGION}

clean:
	go clean

test:
	go test ./...

# Build whatever the output of a project is
# for example:
# 		java → JAR, go → executable binary and/or lib. 
# If the output is just a dockerfile or something else, this target may point to the relevant build step (e.g. "image")
build: configure-env
	./goreleaser build --snapshot --rm-dist --config=.goreleaser.yml

# If a dockerfile is present, this command will build the docker image.
# for goreleaser - it will build the binary and the image (without push the image).
image: configure-env
	./goreleaser release --snapshot --skip-validate --rm-dist --config=.goreleaser.yml

# publish the built image to the registry used by the project
# need be authenticate to the docker registry before, for example using this command:
# aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 889956758113.dkr.ecr.us-west-2.amazonaws.com
publish-image: docker_auth
	docker tag ${DOCKER_REPO_PATH}/${DOCKER_REPO_NAME}:latest ${DOCKER_REPO_PATH}/${DOCKER_REPO_NAME}:${LOCAL_BRANCH}
	docker push ${DOCKER_REPO_PATH}/${DOCKER_REPO_NAME}:latest
	docker push ${DOCKER_REPO_PATH}/${DOCKER_REPO_NAME}:$(LOCAL_BRANCH)

docker-shell:
	docker run -it -v ${PWD}:${WORKING_DIR} -v /var/run/docker.sock:/var/run/docker.sock -w ${WORKING_DIR} docker:git

devbox-shell:
	docker run -it -v ${PWD}:${WORKING_DIR} -w ${WORKING_DIR} \
	 -v /var/run/docker.sock:/var/run/docker.sock \
	 -v $(HOME)/.gitconfig:$(DEVBOX_HOME)/.gitconfig \
     -v $(HOME)/.aws/credentials:$(DEVBOX_HOME)/.aws/credentials \
	 -v $(HOME)/.ssh:$(DEVBOX_HOME)/.ssh \
	 ${DEVBOX_REPO}:${DEVBOX_TAG}


clean-developer:
	rm -rf ./dist
