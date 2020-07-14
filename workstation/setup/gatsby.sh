
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

SETUP_CHECK="$KIRA_SETUP/gatsby-v1" 
if [ ! -f "$SETUP_CHECK" ] ; then
    echo "INFO: Gatsby and its dependencies..."
    echo "INFO: Installing brew..."
    BREW_INSTALL="/tmp/brew_install.sh"
    rm -f $BREW_INSTALL
    curl https://raw.githubusercontent.com/Homebrew/install/master/install.sh -o $BREW_INSTALL
    chmod 777 $BREW_INSTALL
    echo | /bin/su -c "$BREW_INSTALL" - $KIRA_USER
    touch $SETUP_CHECK
else
    echo "INFO: Gatsby was already installed"
fi
