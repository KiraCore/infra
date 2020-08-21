#!/bin/bash

exec 2>&1
set -e
set -x

START_TIME_INFRA="$(date -u +%s)"
source "/etc/profile" &> /dev/null

# Local Update Shortcut:
# (rm -fv $KIRA_WORKSTATION/start.sh) && nano $KIRA_WORKSTATION/start.sh && chmod 777 $KIRA_WORKSTATION/start.sh

SKIP_UPDATE=$1
[ -z "$SKIP_UPDATE" ] && SKIP_UPDATE="False"

echo "------------------------------------------------"
echo "|       STARTED: KIRA INFRA START v0.0.2       |"
echo "|----------------------------------------------|"
echo "|       INFRA BRANCH: $INFRA_BRANCH"
echo "|       SEKAI BRANCH: $SEKAI_BRANCH"
echo "|         INFRA REPO: $INFRA_REPO"
echo "|         SEKAI REPO: $SEKAI_REPO"
echo "| NOTIFICATION EMAIL: $EMAIL_NOTIFY"
echo "|        SKIP UPDATE: $SKIP_UPDATE"
echo "|          KIRA STOP: $KIRA_STOP"
echo "|_______________________________________________"

[ -z "$INFRA_BRANCH" ] && echo "ERROR: INFRA_BRANCH env was not defined" && exit 1
[ -z "$SEKAI_BRANCH" ] && echo "ERROR: SEKAI_BRANCH env was not defined" && exit 1
[ -z "$INFRA_REPO" ] && echo "ERROR: INFRA_REPO env was not defined" && exit 1
[ -z "$SEKAI_REPO" ] && echo "ERROR: SEKAI_REPO env was not defined" && exit 1
[ -z "$EMAIL_NOTIFY" ] && echo "ERROR: EMAIL_NOTIFY env was not defined" && exit 1

$KIRA_SCRIPTS/progress-touch.sh "+1" #1

echo "INFO: Updating infra repository and fetching changes..."
if [ "$SKIP_UPDATE" == "False" ] ; then
    $KIRA_MANAGER/setup.sh "$SKIP_UPDATE" #23(+22)
    source $KIRA_WORKSTATION/start.sh "True" #24(+1)
    exit 0
fi

source $ETC_PROFILE &> /dev/null

if [ "$KIRA_STOP" == "False" ] ; then
    echo "INFO: Stopping infra..."
    source $KIRA_MANAGER/stop.sh
    exit 0
fi

$KIRA_SCRIPTS/container-restart.sh "registry" && $KIRA_SCRIPTS/progress-touch.sh "+1" #25
for ((i=1;i<=$MAX_VALIDATORS;i++)); do

    VALIDATORS_EXIST=$($KIRA_SCRIPTS/containers-exist.sh "validator" || echo "error")
    if [ "$VALIDATORS_EXIST" == "False" ] ; then
        echo "SUCCESS: All validators were deleted"
        break
    fi

    $KIRA_SCRIPTS/container-delete.sh "validator-$i"

    VALIDATOR_EXISTS=$($KIRA_SCRIPTS/container-exists.sh "validator-$i" || echo "error")

    if [ "$VALIDATOR_EXISTS" != "False" ] ; then
        echo "ERROR: Failed to delete validator-$i container, status: ${VALIDATOR_EXISTS}"
        exit 1
    fi
done

$KIRA_SCRIPTS/progress-touch.sh "+1" #26
source $WORKSTATION_SCRIPTS/update-base-image.sh #32(+6)
source $WORKSTATION_SCRIPTS/update-tools-image.sh #37(+5)
source $WORKSTATION_SCRIPTS/update-validator-image.sh #41(+4)

cd $KIRA_WORKSTATION

docker network rm kiranet || echo "Failed to remove kira network"
docker network create --subnet=$KIRA_VALIDATORS_SUBNET kiranet
$KIRA_SCRIPTS/progress-touch.sh "+1" "" "True" #42

GENESIS_SOUCE="/root/.sekaid/config/genesis.json"
GENESIS_DESTINATION="$DOCKER_COMMON/genesis.json"
rm -rfv $DOCKER_COMMON
mkdir -p $DOCKER_COMMON
rm -f $GENESIS_DESTINATION

SEEDS=""
PEERS=""

for ((i=1;i<=$VALIDATORS_COUNT;i++)); do
    echo "INFO: Creating validator-$i container..."
    P2P_LOCAL_PORT="26656"
    P2P_PROXY_PORT="10000"
    RPC_PROXY_PORT="10001"
    LCD_PROXY_PORT="10002"
    RLY_PROXY_PORT="10003" 
    rm -fr "${KIRA_STATE}/validator-$i"
    mkdir -p "${KIRA_STATE}/validator-$i"
    docker run -d \
     --restart=always \
     --name "validator-$i" \
     --network kiranet \
     --ip "101.1.0.$i" \
     -e VALIDATOR_INDEX=$i \
     -e VALIDATORS_COUNT=$VALIDATORS_COUNT \
     -e MONIKER="Local Kira Hub Validator" \
     -e P2P_PROXY_PORT=$P2P_PROXY_PORT \
     -e RPC_PROXY_PORT=$RPC_PROXY_PORT \
     -e LCD_PROXY_PORT=$LCD_PROXY_PORT \
     -e RLY_PROXY_PORT=$RLY_PROXY_PORT \
     -e EMAIL_NOTIFY="$EMAIL_NOTIFY" \
     -e SMTP_SECRET="$SMTP_SECRET" \
     -e NOTIFICATIONS="$NOTIFICATIONS" \
     -e SILENT_MODE="$SILENT_MODE" \
     -e SEEDS="$SEEDS" \
     -e PEERS="$PEERS" \
     -e DEBUG_MODE="True" \
     -v $DOCKER_COMMON:"/common" \
     validator:latest

    $KIRA_SCRIPTS/progress-touch.sh "+1"

    # NOTE: Following actions destroy $i variable so VALIDATOR_INDEX is needed
    echo "INFO: Waiting for validator-$i to start..."
    VALIDATOR_INDEX=$i
    sleep 10
    source $WORKSTATION_SCRIPTS/await-container-init.sh "validator-$i" "300" "10"

    $KIRA_SCRIPTS/progress-touch.sh "+1"

    echo "INFO: Inspecting if validator-$VALIDATOR_INDEX is running..."
    SEKAID_VERSION=$(docker exec -i "validator-$VALIDATOR_INDEX" sekaid version || echo "error")
    if [ "$SEKAID_VERSION" == "error" ] ; then 
        echo "ERROR: sekaid was NOT found" 
        exit 1
    else 
        echo "SUCCESS: sekaid $SEKAID_VERSION was found" 
    fi 

    if [ $VALIDATOR_INDEX -eq 1 ] ; then
        echo "INFO: Saving genesis file..."
        docker cp $NAME:$GENESIS_SOUCE $GENESIS_DESTINATION
        
        if [ ! -f "$GENESIS_DESTINATION" ] ; then
            echo "ERROR: Failed to copy genesis file from validator-$VALIDATOR_INDEX"
            exit 1
        fi
    fi

    NODE_ID=$(docker exec -i "validator-$VALIDATOR_INDEX" sekaid tendermint show-node-id || echo "error")
    # NOTE: New lines have to be removed
    SEEDS=$(echo "${NODE_ID}@101.1.0.$VALIDATOR_INDEX:$P2P_LOCAL_PORT" | xargs | tr -d '\n' | tr -d '\r')
    PEERS=$SEEDS
    # we have to recover the index back before progressing
    i=$VALIDATOR_INDEX
    echo "SUCCESS: validator-$i is up and running, seed: $SEEDS"
done

$KIRA_SCRIPTS/progress-touch.sh "+1" #43+(2*$VALIDATORS_COUNT)

# success_end file is created when docker startup suceeds
echo "------------------------------------------------"
echo "| FINISHED: KIRA INFRA START v0.0.2            |"
echo "|  ELAPSED: $(($(date -u +%s)-$START_TIME_INFRA)) seconds"
echo "------------------------------------------------"