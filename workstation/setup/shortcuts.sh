
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

KIRA_SETUP_GKSUDO="$KIRA_SETUP/gksudo-v0.0.1" 
if [ ! -f "$KIRA_SETUP_GKSUDO" ] ; then
    echo "INFO: Installing gksudo..."
    GKSUDO_PATH=/usr/local/bin/gksudo
    echo "pkexec env DISPLAY=\$DISPLAY XAUTHORITY=\$XAUTHORITY \$@" > $GKSUDO_PATH
    chmod 777 $GKSUDO_PATH
    touch $KIRA_SETUP_GKSUDO
else
    echo "INFO: gksudo was already installed."
fi

KIRA_MANAGER_SCRIPT=$KIRA_MANAGER/start-manager.sh
echo "gnome-terminal --geometry=80x40 --working-directory=/kira -- script -e $KIRA_DUMP/INFRA/manager.log -c '$KIRA_MANAGER/manager.sh ; $SHELL'" > $KIRA_MANAGER_SCRIPT
chmod 777 $KIRA_MANAGER_SCRIPT

KIRA_MANAGER_ENTRY="[Desktop Entry]
Type=Application
Terminal=false
Name=KIRA-MANAGER
Icon=${KIRA_IMG}/kira-core.png
Exec=gksudo $KIRA_MANAGER_SCRIPT
Categories=Application;"

USER_MANAGER_FAVOURITE=$USER_SHORTCUTS/kira-manager.desktop
USER_MANAGER_DESKTOP="/home/$KIRA_USER/Desktop/KIRA-MANAGER.desktop"

mkdir -p "/home/$KIRA_USER/Desktop"
mkdir -p $USER_SHORTCUTS

touch $USER_MANAGER_FAVOURITE
touch $USER_MANAGER_DESKTOP

SFM_CONTENT=$(cat $USER_MANAGER_FAVOURITE || echo "")
SFD_CONTENT=$(cat $USER_MANAGER_DESKTOP || echo "")

if [ -z "$SFM_CONTENT" ] || [ "$SFD_CONTENT" != "$SFM_CONTENT" ] || [ "$KIRA_MANAGER_ENTRY" != "$SFM_CONTENT" ] ; then
    echo "INFO: Updating shortcuts..."
    rm -f $USER_MANAGER_FAVOURITE
    rm -f $USER_MANAGER_DESKTOP

    cat > $USER_MANAGER_FAVOURITE <<< $KIRA_MANAGER_ENTRY
    cat > $USER_MANAGER_DESKTOP <<< $KIRA_MANAGER_ENTRY
    
    chmod +x $USER_MANAGER_DESKTOP
    chmod +x $USER_MANAGER_FAVOURITE
else
    echo "INFO: Shortcuts already exist"
fi


