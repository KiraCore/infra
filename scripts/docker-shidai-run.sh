#!/bin/env bash

VERSION=$1
docker run --name shidai --rm -d -p 8282:8282 -v $(pwd)/interx:/interx -v $(pwd)/sekai:/sekai shidai:$VERSION