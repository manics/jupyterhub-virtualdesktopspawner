#!/bin/bash
set -eu

SCRIPTDIR=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
cd "$SCRIPTDIR"

if command -v podman; then
  CONTAINER=podman
else
  CONTAINER=docker
fi

$CONTAINER run --rm --name localstack -p 4566:4566 \
  -e SERVICES=ec2,iam,sts,ssm \
  -e DEBUG=1 \
  "$@" \
  localstack/localstack:2.0.2
