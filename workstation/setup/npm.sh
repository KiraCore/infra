
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

SETUP_CHECK="$KIRA_SETUP/npm-v0.0.2"
if [ ! -f "$SETUP_CHECK" ] ; then
    echo "INFO: Intalling NPM..."
    apt-get install -y --allow-unauthenticated --allow-downgrades --allow-remove-essential --allow-change-held-packages \
        npm
    npm install -g n 
    n stable
    echo "INFO: Intalling NPM essentials..."
    npm i -g react-static
    touch $SETUP_CHECK
else
    echo "INFO: NPM $(npm --version) was already installed."
fi
