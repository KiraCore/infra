#!/bin/bash

exec 2>&1
set -e
set -x

# Local Update Shortcut:
# (rm -fv $KIRA_WORKSTATION/setup.sh) && nano $KIRA_WORKSTATION/setup.sh && chmod 777 $KIRA_WORKSTATION/setup.sh
source "/etc/profile" &> /dev/null

SKIP_UPDATE=$1
START_TIME=$2
INIT_HASH=$3

[ -z "$START_TIME" ] && START_TIME="$(date -u +%s)"
[ -z "$SKIP_UPDATE" ] && SKIP_UPDATE="False"

[ -z "$DEBUG_MODE" ] && DEBUG_MODE="False"
[ -z "$INIT_HASH" ] && INIT_HASH=$(CDHelper hash SHA256 -p="$KIRA_MANAGER/init.sh" --silent=true || echo "")

echo "------------------------------------------------"
echo "|       STARTED: KIRA INFRA SETUP v0.0.2       |"
echo "|----------------------------------------------|"
echo "|       INFRA BRANCH: $INFRA_BRANCH"
echo "|       SEKAI BRANCH: $SEKAI_BRANCH"
echo "|         INFRA REPO: $INFRA_REPO"
echo "|         SEKAI REPO: $SEKAI_REPO"
echo "| NOTIFICATION EMAIL: $EMAIL_NOTIFY"
echo "|        SKIP UPDATE: $SKIP_UPDATE"
echo "|          KIRA USER: $KIRA_USER"
echo "|_______________________________________________"

[ -z "$INFRA_BRANCH" ] && echo "ERROR: INFRA_BRANCH env was not defined" && exit 1
[ -z "$SEKAI_BRANCH" ] && echo "ERROR: SEKAI_BRANCH env was not defined" && exit 1
[ -z "$INFRA_REPO" ] && echo "ERROR: INFRA_REPO env was not defined" && exit 1
[ -z "$SEKAI_REPO" ] && echo "ERROR: SEKAI_REPO env was not defined" && exit 1
[ -z "$EMAIL_NOTIFY" ] && echo "ERROR: EMAIL_NOTIFY env was not defined" && exit 1
[ -z "$KIRA_USER" ] && echo "ERROR: KIRA_USER env was not defined" && exit 1

$KIRA_SCRIPTS/progress-touch.sh "+1" #1

cd /kira
UPDATED="False"
if [ "$SKIP_UPDATE" == "False" ] ; then
    echo "INFO: Updating Infra, Sekai & SDK..."
    $KIRA_SCRIPTS/git-pull.sh "$INFRA_REPO" "$INFRA_BRANCH" "$KIRA_INFRA" 777 &
    $KIRA_SCRIPTS/git-pull.sh "$SEKAI_REPO" "$SEKAI_BRANCH" "$KIRA_SEKAI" &
    $KIRA_SCRIPTS/git-pull.sh "$SDK_REPO" "$SDK_BRANCH" "$KIRA_SDK" &
    wait < <(jobs -p)
    $KIRA_SCRIPTS/progress-touch.sh "+3" #4

    # we must ensure that recovery files can't be destroyed in the update process and cause a deadlock
    rm -r -f $KIRA_MANAGER
    cp -r $KIRA_WORKSTATION $KIRA_MANAGER
    chmod -R 777 $KIRA_MANAGER

    source $KIRA_WORKSTATION/setup.sh "True" "$START_TIME" "$INIT_HASH" 
    UPDATED="True"
elif [ "$SKIP_UPDATE" == "True" ] ; then
    echo "INFO: Skipping Infra Update..."
else
    echo "ERROR: SKIP_UPDATE propoerty is invalid or undefined"
    exit 1
fi

$KIRA_SCRIPTS/cdhelper-update.sh "v0.6.13" && $KIRA_SCRIPTS/progress-touch.sh "+1" #5
$KIRA_SCRIPTS/awshelper-update.sh "v0.12.4" && $KIRA_SCRIPTS/progress-touch.sh "+1" #6

NEW_INIT_HASH=$(CDHelper hash SHA256 -p="$KIRA_WORKSTATION/init.sh" --silent=true)

if [ "$UPDATED" == "True" ] && [ "$NEW_INIT_HASH" != "$INIT_HASH" ] ; then
   INTERACTIVE="False"
   echo "WARNING: Hash of the init file changed, full reset is required, starting INIT process..."
   source $KIRA_MANAGER/init.sh "False" "$START_TIME" "$DEBUG_MODE" "$INTERACTIVE"
   echo "INFO: Non-interactive init was finalized"
   sleep 3
   exit 0
fi

$KIRA_WORKSTATION/setup/certs.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #7
$KIRA_WORKSTATION/setup/envs.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #8
$KIRA_WORKSTATION/setup/hosts.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #9
$KIRA_WORKSTATION/setup/system.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #10
$KIRA_WORKSTATION/setup/tools.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #11
$KIRA_WORKSTATION/setup/npm.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #12
$KIRA_WORKSTATION/setup/rust.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #13
$KIRA_WORKSTATION/setup/dotnet.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #14
$KIRA_WORKSTATION/setup/systemctl2.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #15
$KIRA_WORKSTATION/setup/docker.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #16
$KIRA_WORKSTATION/setup/golang.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #17
$KIRA_WORKSTATION/setup/nginx.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #18
$KIRA_WORKSTATION/setup/chrome.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #19
$KIRA_WORKSTATION/setup/vscode.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #20
$KIRA_WORKSTATION/setup/registry.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #21
$KIRA_WORKSTATION/setup/goland.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #22
$KIRA_WORKSTATION/setup/shortcuts.sh && $KIRA_SCRIPTS/progress-touch.sh "+1" #23

touch /tmp/rs_manager
touch /tmp/rs_git_manager
touch /tmp/rs_container_manager

echo "------------------------------------------------"
echo "| FINISHED: KIRA INFRA SETUP v0.0.2            |"
echo "|  ELAPSED: $(($(date -u +%s)-$START_TIME)) seconds"
echo "------------------------------------------------"
