
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

KIRA_SETUP_VSCODE="$KIRA_SETUP/goland-v0.0.1" 
if [ ! -f "$KIRA_SETUP_VSCODE" ] ; then
    echo "Installing GoLanD..."
    #INSTALL_DIR=/usr/local/bin/goland
    #VERSION=2020.1.3
    #cd /tmp
    #rm -f -v ./goland-$VERSION.tar.gz 
    #wget https://download-cf.jetbrains.com/go/goland-$VERSION.tar.gz
    #rm -rfv $INSTALL_DIR
    #tar -xvf goland-$VERSION.tar.gz ; mv GoLand-$VERSION $INSTALL_DIR
    #unzip CDHelper-linux-x64.zip -d $INSTALL_DIR
    #chmod -R -v 777 $INSTALL_DIR
    lsb_release -a ; getconf LONG_BIT ; java -version
    snap install goland --classic
else
    echo "GoLand was already installed."
fi
