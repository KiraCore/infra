
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

SKIP_UPDATE=$1
START_TIME=$2
DEBUG_MODE=$3
INTERACTIVE=$4

[ -z "$START_TIME" ] && START_TIME="$(date -u +%s)"
[ -z "$SKIP_UPDATE" ] && SKIP_UPDATE="False"
[ -z "$DEBUG_MODE" ] && DEBUG_MODE="False"
[ -z "$SILENT_MODE" ] && SILENT_MODE="False"
[ -z "$INTERACTIVE" ] && INTERACTIVE="True"

# in the non interactive mode always use explicit shell
[ "$INTERACTIVE" != "True" ] && set -x 

NEW_INTERACTIVE=""
NEW_DEBUG_MODE=""
NEW_INFRA_BRANCH=""
NEW_SEKAI_BRANCH=""
NEW_SDK_BRANCH=""
NEW_NOTIFICATIONS=""
NEW_NOTIFY_EMAIL=""
NEW_SMTP_LOGIN=""
NEW_SMTP_PASSWORD=""
NEW_SSH_KEY=""
NEW_VALIDATORS_COUNT=""

MAX_VALIDATORS=254
[ -z "$INFRA_BRANCH" ] && INFRA_BRANCH="master"
[ -z "$SEKAI_BRANCH" ] && SEKAI_BRANCH="master"
[ -z "$SDK_BRANCH" ] && SDK_BRANCH="master"
[ -z "$DOCS_BRANCH" ] && DOCS_BRANCH="master"
[ -z "$SAIFU_BRANCH" ] && SAIFU_BRANCH="master"
[ -z "$IDOF_BRANCH" ] && IDOF_BRANCH="master"
[ -z "$KIRAF_BRANCH" ] && KIRAF_BRANCH="master"
[ -z "$EMAIL_NOTIFY" ] && EMAIL_NOTIFY="noreply.example.email@gmail.com"
[ -z "$SMTP_LOGIN" ] && SMTP_LOGIN="noreply.example.email@gmail.com"
[ -z "$SMTP_PASSWORD" ] && SMTP_PASSWORD="wpzpjrfsfznyeohs"
[ -z "$INFRA_REPO" ] && INFRA_REPO="https://github.com/KiraCore/infra"
[ -z "$SEKAI_REPO" ] && SEKAI_REPO="https://github.com/KiraCore/sekai"
[ -z "$SDK_REPO" ] && SDK_REPO="https://github.com/KiraCore/cosmos-sdk"
[ -z "$DOCS_REPO" ] && DOCS_REPO="https://github.com/KiraCore/docs"
[ -z "$SAIFU_REPO" ] && SAIFU_REPO="https://github.com/KiraCore/saifu"
[ -z "$SEKAI_REPO_SSH" ] && SEKAI_REPO_SSH="git@github.com:KiraCore/sekai.git"
[ -z "$INFRA_REPO_SSH" ] && INFRA_REPO_SSH="git@github.com:KiraCore/infra.git"
[ -z "$SDK_REPO_SSH" ] && SDK_REPO_SSH="git@github.com:KiraCore/cosmos-sdk.git"
[ -z "$DOCS_REPO_SSH" ] && DOCS_REPO_SSH="git@github.com:KiraCore/docs.git"
[ -z "$IDOF_REPO_SSH" ] && IDOF_REPO_SSH="git@github.com:KiraCore/ido-frontend.git"
[ -z "$KIRAF_REPO_SSH" ] && KIRAF_REPO_SSH="git@github.com:KiraCore/kira-frontend.git"
[ -z "$SAIFU_REPO_SSH" ] && SAIFU_REPO_SSH="git@github.com:KiraCore/saifu.git"
[ -z "$NOTIFICATIONS" ] && NOTIFICATIONS="False"
[ -z "$VALIDATORS_COUNT" ] && VALIDATORS_COUNT=2
[ ! -z "$SUDO_USER" ] && KIRA_USER=$SUDO_USER
[ -z "$KIRA_USER" ] && KIRA_USER=$USER
[ "$KIRA_USER" == "root" ] && KIRA_USER=$(logname)
if [ "$KIRA_USER" == "root" ] ; then 
    echo "You must login as non root user to your machine"
    exit 1
fi

if [ "$SKIP_UPDATE" == "False" ] ; then

    if [ "$INTERACTIVE" == "True" ] ; then
        echo -e "\e[36;1mPress [Y]es/[N]o if you want to run in interactive mode, [ENTER] if '$INTERACTIVE': \e[0m\c" && read  -d'' -s -n1 NEW_INTERACTIVE
        if [ "${NEW_INTERACTIVE,,}" == "y" ] ; then
            INTERACTIVE="True"
        elif [ "${NEW_INTERACTIVE,,}" == "n" ]  ; then
            INTERACTIVE="False"
        fi
    fi
    
    # in the non interactive mode always use explicit shell
    [ "$INTERACTIVE" != "True" ] && set -x 

    #########################################
    # START Installing Essentials
    #########################################
    SSH_PATH=/home/root/.ssh
    KIRA_REPOS=/kira/repos
    KIRA_INFRA="$KIRA_REPOS/infra"
    KIRA_SEKAI="$KIRA_REPOS/sekai"
    KIRA_SDK="$KIRA_REPOS/sdk"
    KIRA_DOCS="$KIRA_REPOS/docs"
    KIRA_SAIFU="$KIRA_REPOS/saifu"
    KIRA_KIRAF="$KIRA_REPOS/kiraf"
    KIRA_IDOF="$KIRA_REPOS/idof"
    KIRA_SETUP=/kira/setup
    KIRA_MANAGER="/kira/manager"
    KIRA_PROGRESS="/kira/progress"
    KIRA_DUMP="/home/$KIRA_USER/Desktop/DUMP"
    KIRA_SCRIPTS="${KIRA_INFRA}/common/scripts"
    KIRA_WORKSTATION="${KIRA_INFRA}/workstation"
    
    mkdir -p $SSH_PATH
    mkdir -p $KIRA_INFRA
    mkdir -p $KIRA_SEKAI
    mkdir -p $KIRA_SDK
    mkdir -p $KIRA_DOCS
    mkdir -p $KIRA_SAIFU
    mkdir -p $KIRA_KIRAF
    mkdir -p $KIRA_IDOF
    mkdir -p $KIRA_SETUP
    mkdir -p $KIRA_MANAGER
    mkdir -p $KIRA_PROGRESS
    rm -rfv $KIRA_DUMP
    mkdir -p "$KIRA_DUMP/INFRA/manager"

    KIRA_SETUP_ESSSENTIALS="$KIRA_SETUP/essentials-v0.0.8" 
    if [ ! -f "$KIRA_SETUP_ESSSENTIALS" ] ; then
        echo "INFO: Installing Essential Packages and Variables..."
        apt-get update -y > /dev/null
        apt-get install -y --allow-unauthenticated --allow-downgrades --allow-remove-essential --allow-change-held-packages \
            software-properties-common apt-transport-https ca-certificates gnupg curl wget git unzip openssh-client openssh-server sshfs > /dev/null

        ln -s /usr/bin/git /bin/git || echo "WARNING: Git symlink already exists"
        git config --add --global user.name dev || echo "WARNING: Failed to set global user name"
        git config --add --global user.email dev@local || echo "WARNING: Failed to set global user email"
        git config --add --global core.autocrlf input || echo "WARNING: Failed to set global autocrlf"
        git config --unset --global core.filemode || echo "WARNING: Failed to unset global filemode"
        git config --add --global core.filemode false || echo "WARNING: Failed to set global filemode"
        git config --add --global pager.branch false || echo "WARNING: Failed to disable branch pager"
    
        echo "INFO: Base Tools Setup..."
        cd /tmp
        INSTALL_DIR="/usr/local/bin"
        rm -f -v ./CDHelper-linux-x64.zip
        wget https://github.com/asmodat/CDHelper/releases/download/v0.6.13/CDHelper-linux-x64.zip
        rm -rfv $INSTALL_DIR
        unzip CDHelper-linux-x64.zip -d $INSTALL_DIR
        chmod -R -v 777 $INSTALL_DIR

        ls -l /bin/CDHelper || echo "Symlink not found"
        rm /bin/CDHelper || echo "Removing old symlink"
        ln -s $INSTALL_DIR/CDHelper/CDHelper /bin/CDHelper || echo "CDHelper symlink already exists"
        
        CDHelper version

        echo "INFO: Setting up Essential Variables and Configs..."
        SSHD_CONFIG="/etc/ssh/sshd_config"
        CDHelper text lineswap --insert="PermitRootLogin yes " --prefix="PermitRootLogin" --path=$SSHD_CONFIG --append-if-found-not=True
        CDHelper text lineswap --insert="PasswordAuthentication yes " --prefix="PasswordAuthentication" --path=$SSHD_CONFIG --append-if-found-not=True
        service ssh restart || echo "WARNING: Failed to restart ssh service"

        CDHelper text lineswap --insert="KIRA_MANAGER=$KIRA_MANAGER" --prefix="KIRA_MANAGER=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_REPOS=$KIRA_REPOS" --prefix="KIRA_REPOS=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_SETUP=$KIRA_SETUP" --prefix="KIRA_SETUP=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_INFRA=$KIRA_INFRA" --prefix="KIRA_INFRA=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_SEKAI=$KIRA_SEKAI" --prefix="KIRA_SEKAI=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_SDK=$KIRA_SDK" --prefix="KIRA_SDK=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_DOCS=$KIRA_DOCS" --prefix="KIRA_DOCS=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_SAIFU=$KIRA_SAIFU" --prefix="KIRA_SAIFU=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_KIRAF=$KIRA_KIRAF" --prefix="KIRA_KIRAF=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_IDOF=$KIRA_IDOF" --prefix="KIRA_IDOF=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_SCRIPTS=$KIRA_SCRIPTS" --prefix="KIRA_SCRIPTS=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="KIRA_WORKSTATION=$KIRA_WORKSTATION" --prefix="KIRA_WORKSTATION=" --path=$ETC_PROFILE --append-if-found-not=True

        SSH_KEY_PUB_PATH=$SSH_PATH/id_rsa.pub
        SSH_KEY_PRIV_PATH=$SSH_PATH/id_rsa
        CDHelper text lineswap --insert="SSH_PATH=$SSH_PATH" --prefix="SSH_PATH=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="SSH_KEY_PUB_PATH=$SSH_KEY_PUB_PATH" --prefix="SSH_KEY_PUB_PATH=" --path=$ETC_PROFILE --append-if-found-not=True
        CDHelper text lineswap --insert="SSH_KEY_PRIV_PATH=$SSH_KEY_PRIV_PATH" --prefix="SSH_KEY_PRIV_PATH=" --path=$ETC_PROFILE --append-if-found-not=True
    
        touch $KIRA_SETUP_ESSSENTIALS
    else
        echo "INFO: Essentials were already installed: $(git --version), Curl, Wget..."
    fi
    
    CDHelper text lineswap --insert="SILENT_MODE=$SILENT_MODE" --prefix="SILENT_MODE=" --path=$ETC_PROFILE --append-if-found-not=True
    CDHelper text lineswap --insert="DEBUG_MODE=$DEBUG_MODE" --prefix="DEBUG_MODE=" --path=$ETC_PROFILE --append-if-found-not=True
    #########################################
    # END Installing Essentials
    #########################################

    [ "$INTERACTIVE" == "True" ] && echo -e "\e[36;1mType INFRA reposiotry branch, [ENTER] if '$INFRA_BRANCH': \e[0m\c" && read NEW_INFRA_BRANCH
    [ ! -z "$NEW_INFRA_BRANCH" ] && INFRA_BRANCH=$NEW_INFRA_BRANCH

    echo "INFO: Updating Infra Repository..."
    rm -rfv $KIRA_INFRA
    mkdir -p $KIRA_INFRA
    git clone --branch $INFRA_BRANCH $INFRA_REPO $KIRA_INFRA
    cd $KIRA_INFRA
    git describe --all --always
    chmod -R 777 $KIRA_INFRA

    # update old processes
    rm -r -f $KIRA_MANAGER
    cp -r $KIRA_WORKSTATION $KIRA_MANAGER
    chmod -R 777 $KIRA_MANAGER

    cd /kira
    source $KIRA_WORKSTATION/init.sh "True" "$START_TIME" "$DEBUG_MODE" "$INTERACTIVE"
    exit 0
else
    chmod 700 $SSH_PATH
    if [ ! -f $SSH_KEY_PRIV_PATH ] ; then
        ssh-keygen -q -t rsa -N '' -f $SSH_KEY_PRIV_PATH 2>/dev/null <<< y >/dev/null
        chmod 600 $SSH_KEY_PRIV_PATH
    fi

    [ "$INTERACTIVE" == "True" ] && echo -e "\e[36;1mType SEKAI reposiotry branch, [ENTER] if '$SEKAI_BRANCH': \e[0m\c" && read NEW_SEKAI_BRANCH
    [ ! -z "$NEW_SEKAI_BRANCH" ] && SEKAI_BRANCH=$NEW_SEKAI_BRANCH

    [ "$INTERACTIVE" == "True" ] && echo -e "\e[36;1mType Cosmos-SDK reposiotry branch, [ENTER] if '$SDK_BRANCH': \e[0m\c" && read NEW_SDK_BRANCH
    [ ! -z "$NEW_SDK_BRANCH" ] && SDK_BRANCH=$NEW_SDK_BRANCH
    
    [ "$INTERACTIVE" == "True" ] && echo -e "\e[36;1mPress [Y]es/[N]o to receive notifications, [ENTER] if '$NOTIFICATIONS': \e[0m\c" && read  -d'' -s -n1 NEW_NOTIFICATIONS
    [ "${NEW_NOTIFICATIONS,,}" == "y" ] && NOTIFICATIONS="True"
    [ "${NEW_NOTIFICATIONS,,}" == "n" ] && NOTIFICATIONS="False"
    
    if [ "$INTERACTIVE" == "True" ] && [ "$NOTIFICATIONS" == "True" ] ; then
        echo -e "\e[36;1mType desired notification email, [ENTER] if '$EMAIL_NOTIFY': \e[0m\c" && read NEW_NOTIFY_EMAIL
        [ ! -z "$NEW_NOTIFY_EMAIL" ] && EMAIL_NOTIFY=$NEW_NOTIFY_EMAIL
        
        echo -e "\e[36;1mType Gmail SMTP login, [ENTER] if '$SMTP_LOGIN': \e[0m\c" && read NEW_SMTP_LOGIN
        [ ! -z "$NEW_SMTP_LOGIN" ] && SMTP_LOGIN=$NEW_SMTP_LOGIN
        
        echo -e "\e[36;1mType Gmail SMTP password, [ENTER] if '$SMTP_PASSWORD': \e[0m\c" && read NEW_SMTP_PASSWORD
        [ ! -z "$NEW_SMTP_PASSWORD" ] && SMTP_PASSWORD=$NEW_SMTP_PASSWORD
    fi
    
    ssh-keygen -y -f $SSH_KEY_PRIV_PATH > $SSH_KEY_PUB_PATH
    chmod 644 $SSH_KEY_PUB_PATH
    SSH_KEY_PUB=$(cat $SSH_KEY_PUB_PATH)

    while : ; do
        echo "INFO: Your current public SSH Key:"
        echo -e "\e[33;1m$SSH_KEY_PUB\e[0m"
        
        [ "$INTERACTIVE" == "True" ] && echo -e "\e[36;1mPress [Y] and paste your PRIVATE git SSH key or press [ENTER] to skip: \e[0m\c" && read -n1 NEW_SSH_KEY
        if [ "${NEW_SSH_KEY,,}" == "y" ] ; then
            echo -e "\nINFO: Press [Ctrl+D] to save input, or use [Ctrl+C] to exit without changes\n"
            set +e
            NEW_SSH_KEY=$(</dev/stdin)
            set -e
        else
            break
        fi

        if [ ! -z "$NEW_SSH_KEY" ] ; then
            rm -rfv $SSH_KEY_PRIV_PATH
            rm -rfv $SSH_KEY_PUB_PATH
            echo -e "$NEW_SSH_KEY" > $SSH_KEY_PRIV_PATH
            chmod 600 $SSH_KEY_PRIV_PATH
            ssh-keygen -y -f $SSH_KEY_PRIV_PATH > $SSH_KEY_PUB_PATH
            chmod 644 $SSH_KEY_PUB_PATH
            SSH_KEY_PUB=$(cat $SSH_KEY_PUB_PATH)
        
            echo "INFO: Your new public SSH Key:"
            echo -e "\e[32;1m$SSH_KEY_PUB\e[0m"
        else
            echo "ERROR: Private key was not submitted"
        fi

        echo -e "\e[36;1mPress [Y]es to confirm or [N]o to try again: \e[0m\c " && read  -d'' -s -n1 OPTION
        [ "${OPTION,,}" == "y" ] && break
        [ "${OPTION,,}" == "n" ] && continue
    done

    echo "INFO: Make sure you copied and saved your private key for recovery purpouses"
    [ "$INTERACTIVE" == "True" ] && echo -e "\e[36;1mPress [Y]es/[N]o to display your private key: \e[0m\c" && read  -d'' -s -n1 SHOW_PRIV_KEY
    if [ "${SHOW_PRIV_KEY,,}" == "y" ] ; then
        echo "INFO: Your private SSH Key: (select, copy and save it for future recovery)"
        echo -e "\e[32;1m$(cat $SSH_KEY_PRIV_PATH)\e[0m"
    fi

    if [ "$INTERACTIVE" == "True" ] && [ ! -z "$NEW_SSH_KEY" ] ; then 
        echo -e "\e[36;1mPress [Y]es/[N]o to display your public key: \e[0m\c" && read  -d'' -s -n1 SHOW_PUB_KEY
        if [ "${SHOW_PUB_KEY,,}" == "y" ] ; then
            echo "INFO: Your public SSH Key:"
            echo -e "\e[32;1m$(cat $SSH_KEY_PUB_PATH)\e[0m"
        fi
    fi

    [ "$INTERACTIVE" == "True" ] && echo -e "\e[36;1mInput number of validators to deploy (min 1, max $MAX_VALIDATORS), [ENTER] if '$VALIDATORS_COUNT': \e[0m\c" && read NEW_VALIDATORS_COUNT
    [ ! -z "$NEW_VALIDATORS_COUNT" ] && [ ! -z "${NEW_VALIDATORS_COUNT##*[!0-9]*}" ] && [ $NEW_VALIDATORS_COUNT -ge 1 ] && [ $NEW_VALIDATORS_COUNT -le $MAX_VALIDATORS ] && VALIDATORS_COUNT=$NEW_VALIDATORS_COUNT

    echo -e "\e[33;1m------------------------------------------------"
    echo "|       STARTED: KIRA INFRA INIT v0.0.2        |"
    echo "|----------------------------------------------|"
    echo "|         DEBUG MODE: $DEBUG_MODE"
    echo "|       INFRA BRANCH: $INFRA_BRANCH"
    echo "|       SEKAI BRANCH: $SEKAI_BRANCH"
    echo "|         SDK BRANCH: $SDK_BRANCH"
    echo "|         INFRA REPO: $INFRA_REPO"
    echo "|         SEKAI REPO: $SEKAI_REPO"
    echo "|      NOTIFICATIONS: $NOTIFICATIONS"
    echo "| NOTIFICATION EMAIL: $EMAIL_NOTIFY"
    echo "|         SMTP LOGIN: $SMTP_LOGIN"
    echo "|      SMTP PASSWORD: $SMTP_PASSWORD"
    echo "|          KIRA USER: $KIRA_USER"
    echo "|   VALIDATORS COUNT: $VALIDATORS_COUNT"
    echo "| PUBLIC GIT SSH KEY: $(echo $SSH_KEY_PUB | head -c 24)...$(echo $SSH_KEY_PUB | tail -c 24)"
    echo -e "------------------------------------------------\e[0m"
    
    [ "$INTERACTIVE" == "True" ] && echo -e "\e[36;1mPress [ENTER] to confirm or any other key to exit: \e[0m\c" && read  -d'' -s -n1 ACCEPT
    [ ! -z "$ACCEPT" ] && exit 1
fi

CDHelper text lineswap --insert="NOTIFICATIONS=$NOTIFICATIONS" --prefix="NOTIFICATIONS=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SMTP_LOGIN=$SMTP_LOGIN" --prefix="SMTP_LOGIN=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SMTP_PASSWORD=$SMTP_PASSWORD" --prefix="SMTP_PASSWORD=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SMTP_SECRET={\\\"host\\\":\\\"smtp.gmail.com\\\",\\\"port\\\":\\\"587\\\",\\\"ssl\\\":true,\\\"login\\\":\\\"$SMTP_LOGIN\\\",\\\"password\\\":\\\"$SMTP_PASSWORD\\\"}" --prefix="SMTP_SECRET=" --path=$ETC_PROFILE --append-if-found-not=True

CDHelper text lineswap --insert="KIRA_DUMP=$KIRA_DUMP" --prefix="KIRA_DUMP=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="KIRA_PROGRESS=$KIRA_PROGRESS" --prefix="KIRA_PROGRESS=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="KIRA_USER=$KIRA_USER" --prefix="KIRA_USER=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="USER_SHORTCUTS=/home/$KIRA_USER/.local/share/applications" --prefix="USER_SHORTCUTS=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="EMAIL_NOTIFY=$EMAIL_NOTIFY" --prefix="EMAIL_NOTIFY=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="INFRA_BRANCH=$INFRA_BRANCH" --prefix="INFRA_BRANCH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SEKAI_BRANCH=$SEKAI_BRANCH" --prefix="SEKAI_BRANCH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="DOCS_BRANCH=$DOCS_BRANCH" --prefix="DOCS_BRANCH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SDK_BRANCH=$SDK_BRANCH" --prefix="SDK_BRANCH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SAIFU_BRANCH=$SAIFU_BRANCH" --prefix="SAIFU_BRANCH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="KIRAF_BRANCH=$KIRAF_BRANCH" --prefix="KIRAF_BRANCH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="IDOF_BRANCH=$IDOF_BRANCH" --prefix="IDOF_BRANCH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="INFRA_REPO=$INFRA_REPO" --prefix="INFRA_REPO=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SEKAI_REPO=$SEKAI_REPO" --prefix="SEKAI_REPO=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SDK_REPO=$SDK_REPO" --prefix="SDK_REPO=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="DOCS_REPO=$DOCS_REPO" --prefix="DOCS_REPO=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SAIFU_REPO=$SAIFU_REPO" --prefix="SAIFU_REPO=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SEKAI_REPO_SSH=$SEKAI_REPO_SSH" --prefix="SEKAI_REPO_SSH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="INFRA_REPO_SSH=$INFRA_REPO_SSH" --prefix="INFRA_REPO_SSH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="SDK_REPO_SSH=$SDK_REPO_SSH" --prefix="SDK_REPO_SSH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="KIRAF_REPO_SSH=$KIRAF_REPO_SSH" --prefix="KIRAF_REPO_SSH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="IDOF_REPO_SSH=$IDOF_REPO_SSH" --prefix="IDOF_REPO_SSH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="DOCS_REPO_SSH=$DOCS_REPO_SSH" --prefix="DOCS_REPO_SSH=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="VALIDATORS_COUNT=$VALIDATORS_COUNT" --prefix="VALIDATORS_COUNT=" --path=$ETC_PROFILE --append-if-found-not=True
CDHelper text lineswap --insert="MAX_VALIDATORS=$MAX_VALIDATORS" --prefix="MAX_VALIDATORS=" --path=$ETC_PROFILE --append-if-found-not=True




chmod 777 $ETC_PROFILE

cd /kira
source $KIRA_WORKSTATION/start.sh "False"

echo "------------------------------------------------"
echo "| FINISHED: KIRA INFRA INIT v0.0.2             |"
echo "|  ELAPSED: $(($(date -u +%s)-$START_TIME)) seconds"
echo "------------------------------------------------"

