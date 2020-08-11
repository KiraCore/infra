
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null
source /root/.bashrc &> /dev/null

SETUP_CHECK="$KIRA_SETUP/gatsby-v2" 
if [ ! -f "$SETUP_CHECK" ] ; then
    echo "INFO: Gatsby and its dependencies..."
    echo "INFO: Installing brew..."
    BREW_INSTALL="/tmp/brew_install.sh"
    rm -f $BREW_INSTALL
    curl https://raw.githubusercontent.com/Homebrew/install/master/install.sh -o $BREW_INSTALL
    chmod 777 $BREW_INSTALL
    echo | /bin/su -c "$BREW_INSTALL" - $KIRA_USER
    echo "INFO: Installing node..."
    /bin/su -c "brew install node" - $KIRA_USER
    echo "INFO: Installing nvm..."
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash
    source /root/.bashrc
    echo "INFO: Installing gatsby..."
    npm install -g gatsby-cli
    gatsby -v
    touch $SETUP_CHECK
else
    echo "INFO: NVM v$(nvm --version) was already installed"
    echo "INFO: node $(node --version) was already installed"
    echo "INFO: $(gatsby -v) was already installed"
fi
