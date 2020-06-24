#!/bin/bash

exec 2>&1
set -e
set -x

START_TIME_IMAGE_UPDATE="$(date -u +%s)"
source "/etc/profile" &> /dev/null

SEKAI_HASH=$($KIRA_SCRIPTS/git-hash.sh $KIRA_SEKAI)
SDK_HASH=$($KIRA_SCRIPTS/git-hash.sh $KIRA_SDK)
SEKAI_INTEGRITY="_${SEKAI_HASH}_${SDK_HASH}"

echo "------------------------------------------------"
echo "|    STARTED: VALIDATOR IMAGE UPDATE v0.0.2    |"
echo "------------------------------------------------"
echo "| IMAGE NAME: validator"
echo "|  IMAGE TAG: latest"
echo "|       REPO: $SEKAI_REPO"
echo "|     BRANCH: $SEKAI_BRANCH"
echo "|  INTEGRITY: $SEKAI_INTEGRITY"
echo "------------------------------------------------"

VALIDATOR_IMAGE_EXISTS=$($WORKSTATION_SCRIPTS/image-updated.sh "$KIRA_DOCKER/validator" "validator" "latest" "$SEKAI_INTEGRITY" || echo "error")
if [ "$VALIDATOR_IMAGE_EXISTS" == "False" ] ; then
    echo "All imags were updated, starting validator image..."
    $WORKSTATION_SCRIPTS/update-image.sh "$KIRA_DOCKER/validator" "validator" "latest" "$SEKAI_INTEGRITY" "REPO=$SEKAI_REPO" "BRANCH=$SEKAI_BRANCH" #4
elif [ "$VALIDATOR_IMAGE_EXISTS" == "True" ] ; then
    echo "INFO: validator-image is up to date"
    $KIRA_SCRIPTS/progress-touch.sh "+4" #4
else
    echo "ERROR: Failed to test if validator image exists"
    exit 1
fi

echo "------------------------------------------------"
echo "| FINISHED: VALIDATOR IMAGE UPDATE v0.0.2      |"
echo "|  ELAPSED: $(($(date -u +%s)-$START_TIME_IMAGE_UPDATE)) seconds"
echo "------------------------------------------------"
