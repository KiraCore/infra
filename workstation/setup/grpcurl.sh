
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

GRPCURL_VERSION="1.7.0"
GRPCURL_PATH="${GOPATH}/src/github.com/fullstorydev/grpcurl"

SETUP_CHECK="$KIRA_SETUP/grpc-v${GRPCURL_VERSION}" 
if [ ! -f "$SETUP_CHECK" ] ; then
    echo "INFO: Installing latest grpc version $GRPCURL_VERSION https://github.com/fullstorydev/grpcurl ..."
    rm -f $GRPCURL_PATH
    mkdir -p $GRPCURL_PATH
    cd $GRPCURL_PATH
    rm -fv ./v$GRPCURL_VERSION.tar.gz
    wget "https://github.com/fullstorydev/grpcurl/archive/v${GRPCURL_VERSION}.tar.gz"
    tar -zxvf ./v$GRPCURL_VERSION.tar.gz
    cd ./grpcurl-$GRPCURL_VERSION/cmd/grpcurl/
    go build
    rm -fv /bin/grpcurl
    ln -s $GRPCURL_PATH/grpcurl-$GRPCURL_VERSION/cmd/grpcurl/grpcurl /bin/grpcurl || echo "grpcurl symlink already exists"
    touch $SETUP_CHECK
else
    echo "INFO: grpcurl was already installed"
fi

