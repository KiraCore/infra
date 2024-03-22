#!/bin/env bash

VERSION=$1

docker build -t shidai:$VERSION -f shidai.Dockerfile .
