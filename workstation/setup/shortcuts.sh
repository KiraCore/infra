
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
echo "gnome-terminal --geometry=80x30 --working-directory=/kira -- script -e $KIRA_DUMP/INFRA/manager.log -c '$KIRA_MANAGER/manager.sh ; $SHELL'" > $KIRA_MANAGER_SCRIPT
chmod 777 $KIRA_MANAGER_SCRIPT

KIRA_MANAGER_ENTRY="[Desktop Entry]
Type=Application
Terminal=false
Name=KIRA-MANAGER
Icon=${KIRA_IMG}/kira-core.png
Exec=gksudo $KIRA_MANAGER_SCRIPT
Categories=Application;"

USER_MANAGER_FAVOURITE=$USER_SHORTCUTS/kira-manager.desktop

cat > $USER_MANAGER_FAVOURITE <<< $KIRA_MANAGER_ENTRY

chmod +x $USER_MANAGER_FAVOURITE

USER_MANAGER_DESKTOP="/home/$KIRA_USER/Desktop/KIRA-MANAGER.desktop"

cat > $USER_MANAGER_DESKTOP <<< $KIRA_MANAGER_ENTRY

chmod +x $USER_MANAGER_DESKTOP 


