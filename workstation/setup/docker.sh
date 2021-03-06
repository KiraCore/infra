
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

VERSION=$(docker -v || echo "Error")
SETUP_CHECK="$KIRA_SETUP/docker-v0.0.2" 
if [ ! -f "$SETUP_CHECK" ] || [ "$VERSION" == "Error" ] ; then
    echo "INFO: Installing Docker..."
    apt-get update
    apt install docker.io -y
    systemctl enable --now docker
    docker -v
    touch $SETUP_CHECK
else
    echo "INFO: Docker $(docker -v) was already installed"
fi
