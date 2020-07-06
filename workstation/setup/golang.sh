
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

KIRA_SETUP_GO="$KIRA_SETUP/go-v${GO_VERSION}" 
if [ ! -f "$KIRA_SETUP_GO" ] ; then
    echo "INFO: Installing latest go version $GO_VERSION https://golang.org/doc/install ..."
    wget https://dl.google.com/go/go$GO_VERSION.linux-amd64.tar.gz
    tar -C /usr/local -xvf go$GO_VERSION.linux-amd64.tar.gz
    go version
    go env
    touch $KIRA_SETUP_GO
else
    echo "INFO: Go $(go version) was already installed"
fi

KIRA_SETUP_GO_TOOLS="$KIRA_SETUP/go-tools-v1" 
if [ ! -f "$KIRA_SETUP_GO_TOOLS" ] ; then
    echo "INFO: Installing latest go tools..."
    go get -v golang.org/x/tools/cmd/guru
    go get -v golang.org/x/tools/cmd/stringer
    go get -v golang.org/x/tools/cmd/toolstash
    go get -v golang.org/x/tools/cmd/godoc
    go get -v golang.org/x/tools/cmd/gotype
    go get -v golang.org/x/tools/gopls
    go get -v golang.org/x/tools/cover
    go get -v golang.org/x/tools/go/ast/astutil
    go get -v golang.org/x/tools/go/buildutil
    go get -v golang.org/x/tools/go/expect
    go get -v golang.org/x/tools/go/loader
    go get -v golang.org/x/tools/go/packages
    go get -v golang.org/x/tools/go/ssa
    go get -v golang.org/x/tools/imports
    go get -v golang.org/x/tools/txtar
    go get -v github.com/ramya-rao-a/go-outline
    go get -v github.com/rogpeppe/godef
    touch $KIRA_SETUP_GO_TOOLS
else
    echo "INFO: Go tools were already installed"
fi