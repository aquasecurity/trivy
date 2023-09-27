#!/bin/bash

DOCKER_REPO=$1
DOCKER_REGION=$2
CRED_FILE=$3

set -x

if [[ ${DOCKER_REPO} == public.ecr.aws/* ]]; then
    if [ -z "$CRED_FILE" ]; then
        #In case CRED FILE is empty
        aws ecr-public get-login-password --region ${DOCKER_REGION} | docker login --username AWS --password-stdin ${DOCKER_REPO}
    else
        aws ecr-public get-login-password --region ${DOCKER_REGION} > $CRED_FILE
        cat $CRED_FILE | docker login --username AWS --password-stdin ${DOCKER_REPO}
    fi
elif [[ ${DOCKER_REPO} == gcr.io* ]]; then
    cat /home/devbox/alcide-rnd-service-account.json | docker login https://gcr.io  -u _json_key --password-stdin
else
    if [ -z "$CRED_FILE" ]; then
        #In case CRED FILE is empty
        aws ecr get-login-password --region ${DOCKER_REGION} | docker login --username AWS --password-stdin ${DOCKER_REPO}        
    else
        aws ecr get-login-password --region ${DOCKER_REGION} > $CRED_FILE
        cat $CRED_FILE | docker login --username AWS --password-stdin ${DOCKER_REPO}
    fi
fi

set +x