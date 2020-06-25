
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

KIRA_SETUP_VSCODE="$KIRA_SETUP/vscode-v0.0.3" 
if [ ! -f "$KIRA_SETUP_VSCODE" ] ; then
    echo "Installing Visual Studio Code..."
    mkdir -p /usr/code
    apt update -y
    # apt upgrade
    apt install code -y
    code --version --user-data-dir=/usr/code
    touch $KIRA_SETUP_VSCODE

    echo "Installing VSCode Extentions..."
    code --list-extensions --user-data-dir=/usr/code
    code --force --install-extension bmalehorn.shell-syntax --user-data-dir=/usr/code || echo "WARNING: Faile dto install `bmalehorn.shell-syntax` extentions"
    code --force --install-extension formulahendry.code-runner --user-data-dir=/usr/code || echo "WARNING: Faile dto install `formulahendry.code-runner` extentions"
    code --force --install-extension ms-azuretools.vscode-docker --user-data-dir=/usr/code || echo "WARNING: Faile dto install `ms-azuretools.vscode-docker` extentions"
    code --force --install-extension AdrianSanguineti.json-parse-validator --user-data-dir=/usr/code || echo "WARNING: Faile dto install `AdrianSanguineti.json-parse-validator` extentions"
    code --force --install-extension ZainChen.json --user-data-dir=/usr/code || echo "WARNING: Faile dto install `ZainChen.json` extentions"
    code --force --install-extension yzhang.markdown-all-in-one --user-data-dir=/usr/code || echo "WARNING: Faile dto install `yzhang.markdown-all-in-one` extentions"
    code --force --install-extension shd101wyy.markdown-preview-enhanced --user-data-dir=/usr/code || echo "WARNING: Faile dto install `shd101wyy.markdown-preview-enhanced` extentions"
    code --force --install-extension bierner.markdown-emoji --user-data-dir=/usr/code || echo "WARNING: Faile dto install `bierner.markdown-emoji` extentions"
    code --force --install-extension christian-kohler.npm-intellisense --user-data-dir=/usr/code || echo "WARNING: Faile dto install `christian-kohler.npm-intellisense` extentions"
    code --force --install-extension tht13.python --user-data-dir=/usr/code || echo "WARNING: Faile dto install `tht13.python` extentions"
    code --force --install-extension medo64.render-crlf --user-data-dir=/usr/code || echo "WARNING: Faile dto install `medo64.render-crlf` extentions"
    code --force --install-extension tomoki1207.pdf --user-data-dir=/usr/code || echo "WARNING: Faile dto install `tomoki1207.pdf` extentions"
    code --force --install-extension redhat.vscode-yaml --user-data-dir=/usr/code || echo "WARNING: Faile dto install `redhat.vscode-yaml` extentions"
    code --force --install-extension golang.Go --user-data-dir=/usr/code || echo "WARNING: Faile dto install `golang.Go` extentions"
    code --list-extensions --user-data-dir=/usr/code
else
    echo "Visual Studio Code $(code --version --user-data-dir=/usr/code) was already installed."
fi
