#!/usr/bin/env bash

# Copyright 2018 Twitch Interactive, Inc.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not
# use this file except in compliance with the License. A copy of the License is
# located at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

which protoc
PROTOC_EXISTS=$?
if [ $PROTOC_EXISTS -eq 0 ]; then
	PROTOC_VERSION=`protoc --version`
    if [[ $PROTOC_VERSION == "libprotoc 3."* ]]; then
        echo "protoc version: $PROTOC_VERSION"
		exit 0
	fi
	echo "required protoc v3, but found: $PROTOC_VERSION"
	exit 1
fi
echo "Please install protoc v3. See https://grpc.io/docs/protoc-installation/, for example in MacOS: brew install protobuf"
exit 1
