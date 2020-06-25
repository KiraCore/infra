#!/bin/bash

exec 2>&1
set -e

# Local Update Shortcut:
# (rm -fv $KIRA_MANAGER/manager.sh) && nano $KIRA_MANAGER/manager.sh && chmod 777 $KIRA_MANAGER/manager.sh && touch /tmp/rs_manager

LOOP_FILE="/tmp/manager_loop"
VARS_FILE="/tmp/manager_vars"
RESTART_SIGNAL="/tmp/rs_manager"
source "/etc/profile" &> /dev/null
if [ "$DEBUG_MODE" == "True" ] ; then set -x ; else set +x ; fi

function checkContainerStatus() {
    i="$1" && name="$2" && output="$3"
    CONTAINER_ID=$(docker ps --no-trunc -aqf name=$name || echo "")

    echo "CONTAINER_NAME_$i=$name" >> $output
    echo "CONTAINER_ID_$i=$CONTAINER_ID" >> $output
    [ -z "$CONTAINER_ID" ] && echo "SUCCESS=False" >> $output && exit 0
    CONTAINER_STATUS=$(docker inspect $CONTAINER_ID 2>/dev/null | jq -r '.[0].State.Status' 2>/dev/null || echo "error")
    [ "$CONTAINER_STATUS" != "exited" ] && echo "EXITED=False" >> $output

    #Add block height info
    if [ "$CONTAINER_STATUS" == "running" ] ; then
        HEALTH=$(docker inspect $(docker ps --no-trunc -aqf name=$name ) 2>/dev/null | jq -r '.[0].State.Health.Status' 2>/dev/null || echo "")
        [ "$HEALTH" != "healthy" ] && [ "$HEALTH" != "null" ] && echo "SUCCESS=False" >> $output
        
        if [ ! -z "$HEALTH" ] && [ "$HEALTH" != "null" ] ; then
            CONTAINER_STATUS=$HEALTH
            HEIGHT=$(docker exec -i $name sekaicli status 2>/dev/null | jq -r '.sync_info.latest_block_height' 2>/dev/null | xargs || echo "")
            [ ! -z "$HEIGHT" ] && CONTAINER_STATUS="$CONTAINER_STATUS:$HEIGHT"
        fi
    else
        [ -z "$CONTAINER_STATUS" ] && CONTAINER_STATUS="error"
        echo "SUCCESS=False" >> $output
    fi

    echo "CONTAINER_STATUS_$i=$CONTAINER_STATUS" >> $output
}


while : ; do
    START_TIME="$(date -u +%s)"
    [ -f $RESTART_SIGNAL ] && break
    
    SUCCESS="True" # all passed
    EXITED="True" # all exited
    rm -f $VARS_FILE && touch $VARS_FILE
    CONTAINERS=$(docker ps -a | awk '{if(NR>1) print $NF}' | tac)
    i=-1 ; for name in $CONTAINERS ; do i=$((i+1))
        checkContainerStatus "$i" "$name" "$VARS_FILE" &
    done

    CONTAINERS_COUNT=$((i+1))
    [ $CONTAINERS_COUNT -le $VALIDATORS_COUNT ] && SUCCESS="False"

    wait
    source $VARS_FILE
    clear
    
    echo -e "\e[33;1m------------------------------------------------"
    echo "|         KIRA NETWORK MANAGER v0.0.5          |"
    echo "|             $(date '+%d/%m/%Y %H:%M:%S')              |"
    [ "$SUCCESS" == "True" ] && echo -e "|\e[0m\e[32;1m     SUCCESS, INFRASTRUCTURE IS HEALTHY       \e[33;1m|"
    [ "$SUCCESS" != "True" ] && echo -e "|\e[0m\e[31;1m ISSUES DETECTED, INFRASTRUCTURE IS UNHEALTHY \e[33;1m|"
    echo "|----------------------------------------------| [status:height]"
    i=-1 ; for name in $CONTAINERS ; do i=$((i+1))
        CONTAINER_ID="CONTAINER_ID_$i" && [ -z "${!CONTAINER_ID}" ] && continue
        CONTAINER_STATUS="CONTAINER_STATUS_$i" && status="${!CONTAINER_STATUS}"
        LABEL="| [$i] | Inspect $name container                 "
        echo "${LABEL:0:46} : $status"
    done
    [ "$EXITED" == "False" ] && [ "$CONTAINERS_COUNT" != "0" ] && \
    
    echo "|----------------------------------------------|"
    echo "| [A] | Mange INFRA Git Repository             : $INFRA_BRANCH"
    echo "| [B] | Mange SEKAI Git Repository             : $SEKAI_BRANCH"
    echo "| [C] | Mange COSMOS-SDK Git Repository        : $SDK_BRANCH"
    echo "|----------------------------------------------|"
    echo "| [V] | VIEW All Repos in Code Editor          |"
    echo "| [L] | Show All LOGS in Code Editor           |"
    echo "| [S] | STOP All Containers                    |"
    [ "$CONTAINERS_COUNT" != "0" ] && \
    echo "| [R] | Re-START All Containers                |"
    echo "| [I] | Re-INITALIZE Environment               |"
    echo "| [H] | HARD-Reset Repos & Infrastructure      |"
    echo "| [D] | DELETE Repos & Infrastructure          |"
    echo "|----------------------------------------------|"
    echo "| [X] | Exit | [W] | Refresh Window            |"
    echo -e "------------------------------------------------\e[0m"
    
    echo "Input option then press [ENTER] or [SPACE]: " && rm -f $LOOP_FILE && touch $LOOP_FILE && OPTION=""
    while : ; do
        [ -f $LOOP_FILE ] && OPTION=$(cat $LOOP_FILE || echo "")
        [ -f $RESTART_SIGNAL ] && break
        [ -z "$OPTION" ] && [ $(($(date -u +%s)-$START_TIME)) -ge 10 ] && break
        read -n 1 -t 5 KEY || continue
        [ ! -z "$KEY" ] && echo "${OPTION}${KEY}" > $LOOP_FILE
        [ -z "$KEY" ] && break
    done
    OPTION=$(cat $LOOP_FILE || echo "") && [ -z "$OPTION" ] && continue
    ACCEPT="" && while [ "${ACCEPT,,}" != "y" ] && [ "${ACCEPT,,}" != "n" ] ; do echo -e "\e[36;1mPress [Y]es to confirm option (${OPTION^^}) or [N]o to cancel: \e[0m\c" && read  -d'' -s -n1 ACCEPT ; done
    echo "" && [ "${ACCEPT,,}" == "n" ] && echo "WARINIG: Operation was cancelled" && continue

    i=-1 ; for name in $CONTAINERS ; do i=$((i+1))
        if [ "$OPTION" == "$i" ] ; then
            gnome-terminal -- script -e "$KIRA_DUMP/INFRA/manager/container-$name.log" -c "$KIRA_MANAGER/container-manager.sh $name ; read -d'' -s -n1 -p 'Press any key to exit and save logs...' && exit"
            BREAK="True"
            break
        fi 
    done
    if [ "${OPTION,,}" == "v" ] ; then
        echo "INFO: Starting code editor..."
        USER_DATA_DIR="/usr/code$KIRA_REPOS"
        rm -rf $USER_DATA_DIR
        mkdir -p $USER_DATA_DIR
        code --user-data-dir $USER_DATA_DIR $KIRA_REPOS
        continue
    elif [ "${OPTION,,}" == "l" ] ; then
        echo "INFO: Please wait, dumping logs form all $CONTAINERS_COUNT containers..."
        $KIRA_SCRIPTS/progress-touch.sh "*0" "prg-logs"
        for name in $CONTAINERS ; do
            $WORKSTATION_SCRIPTS/dump-logs.sh $name > "$KIRA_DUMP/INFRA/dump_${name}.log" 2>&1 &
            PID=$!
            $KIRA_SCRIPTS/progress-touch.sh "+1;$CONTAINERS_COUNT;48;$PID" "prg-logs" 2> "$KIRA_DUMP/INFRA/progress.log" || echo -e "\nWARNING: Progress tool failed"
            FAILURE="False" && wait $PID || FAILURE="True"
            [ "$FAILURE" == "True" ] && echo -e "\nERROR: Failed to dump $name container logs" && read -d'' -s -n1 -p 'Press any key to continue...'
        done
        echo -e "\nINFO: Starting code editor..."
        USER_DATA_DIR="/usr/code$KIRA_DUMP"
        rm -rf $USER_DATA_DIR
        mkdir -p $USER_DATA_DIR
        code --user-data-dir $USER_DATA_DIR $KIRA_DUMP
        continue
    elif [ "${OPTION,,}" == "a" ] ; then
        echo "INFO: Starting git manager..."
        gnome-terminal -- script -e $KIRA_DUMP/INFRA/manager/git-infra.log -c "$KIRA_MANAGER/git-manager.sh \"$INFRA_REPO_SSH\" \"$INFRA_REPO\" \"$INFRA_BRANCH\" \"$KIRA_INFRA\" \"INFRA_BRANCH\" ; read -d'' -s -n1 -p 'Press any key to exit...' && exit"
        break
    elif [ "${OPTION,,}" == "b" ] ; then
        echo "INFO: Starting git manager..."
        gnome-terminal -- script -e $KIRA_DUMP/INFRA/manager/git-sekai.log -c "$KIRA_MANAGER/git-manager.sh \"$SEKAI_REPO_SSH\" \"$SEKAI_REPO\" \"$SEKAI_BRANCH\" \"$KIRA_SEKAI\" \"SEKAI_BRANCH\" ; read -d'' -s -n1 -p 'Press any key to exit...' && exit"
        break
    elif [ "${OPTION,,}" == "c" ] ; then
        echo "INFO: Starting git manager..."
        gnome-terminal -- script -e $KIRA_DUMP/INFRA/manager/git-sdk.log -c "$KIRA_MANAGER/git-manager.sh \"$SDK_REPO_SSH\" \"$SDK_REPO\" \"$SDK_BRANCH\" \"$KIRA_SDK\" \"SDK_BRANCH\" ; read -d'' -s -n1 -p 'Press any key to exit...' && exit"
        break
    elif [ "${OPTION,,}" == "i" ] ; then
        echo "INFO: Wiping and re-initializing..."
        $KIRA_SCRIPTS/progress-touch.sh "*0" 
        gnome-terminal --disable-factory -- script -e $KIRA_DUMP/INFRA/init.log -c "$KIRA_MANAGER/init.sh False ; read -d'' -s -n1 -p 'Press any key to exit and save logs...' && exit" &
        PID=$! && sleep 2 && echo -e "\e[33;1mWARNING: You have to wait for process $PID to finish then close the new terminal\e[0m"
        $KIRA_SCRIPTS/progress-touch.sh "+0;$((62+(2*$VALIDATORS_COUNT)));48;$PID" 2> "$KIRA_DUMP/INFRA/progress.log" || echo -e "\nWARNING: Progress tool failed"
        FAILURE="False" && wait $PID || FAILURE="True"
        [ "$FAILURE" == "False" ] && echo -e "\nSUCCESS: Infra was stopped" && break
        [ "$FAILURE" == "True" ] && echo -e "\nERROR: Init script failed, logs are available in the '$KIRA_DUMP' directory"
        break
    elif [ "${OPTION,,}" == "s" ] ; then
        echo "INFO: Stopping infrastructure..."
        $KIRA_SCRIPTS/progress-touch.sh "*0" 
        $KIRA_MANAGER/stop.sh > "$KIRA_DUMP/INFRA/manager/stop.log" 2>&1 &
        PID=$! && echo -e "\e[33;1mWARNING: You have to wait for process $PID to finish\e[0m"
        $KIRA_SCRIPTS/progress-touch.sh "+0;$((2+$CONTAINERS_COUNT));48;$PID" 2> "$KIRA_DUMP/INFRA/progress.log" || echo -e "\nWARNING: Progress tool failed"
        FAILURE="False" && wait $PID || FAILURE="True"
        [ "$FAILURE" == "True" ] && echo -e "\nERROR: Stop script failed, logs are available in the '$KIRA_DUMP' directory" && read -d'' -s -n1 -p 'Press any key to continue...'
        [ "$FAILURE" == "False" ] && echo -e "\nSUCCESS: Infra was stopped"
        break
    elif [ "${OPTION,,}" == "r" ] ; then
        echo "INFO: Re-starting infrastructure..."
        $KIRA_SCRIPTS/progress-touch.sh "*0" 
        $KIRA_MANAGER/restart.sh > "$KIRA_DUMP/INFRA/manager/restart.log" 2>&1 &
        PID=$! && echo -e "\e[33;1mWARNING: You have to wait for process $PID to finish\e[0m"
        $KIRA_SCRIPTS/progress-touch.sh "+0;$((2+$CONTAINERS_COUNT));48;$PID" 2> "$KIRA_DUMP/INFRA/progress.log" || echo -e "\nWARNING: Progress tool failed"
        FAILURE="False" && wait $PID || FAILURE="True"
        [ "$FAILURE" == "True" ] && echo -e "\nERROR: Restart script failed, logs are available in the '$KIRA_DUMP' directory" && read -d'' -s -n1 -p 'Press any key to continue...'
        [ "$FAILURE" == "False" ] && echo -e "\nSUCCESS: Infra was restarted" 
        break
    elif [ "${OPTION,,}" == "h" ] ; then
        echo "INFO: Wiping and Restarting infra..."
        $KIRA_SCRIPTS/progress-touch.sh "*0" 
        $KIRA_MANAGER/start.sh > "$KIRA_DUMP/INFRA/manager/start.log" 2>&1 &
        PID=$! && echo -e "\e[33;1mWARNING: You have to wait for process $PID to finish\e[0m"
        $KIRA_SCRIPTS/progress-touch.sh "+0;$((62+(2*$VALIDATORS_COUNT)));48;$PID" 2> "$KIRA_DUMP/INFRA/progress.log" || echo -e "\nWARNING: Progress tool failed"
        FAILURE="False" && wait $PID || FAILURE="True"
        [ "$FAILURE" == "True" ] && echo -e "\nERROR: Start script failed, logs are available in the '$KIRA_DUMP' directory" && read -d'' -s -n1 -p 'Press any key to continue...'
        [ "$FAILURE" == "False" ] && echo -e "\nSUCCESS: Infra was wiped and restarted"
        break
    elif [ "${OPTION,,}" == "d" ] ; then
        echo "INFO: Wiping and removing infra..."
        $KIRA_SCRIPTS/progress-touch.sh "*0" 
        $KIRA_MANAGER/delete.sh > "$KIRA_DUMP/INFRA/manager/delete.log" 2>&1 &
        PID=$! && echo -e "\e[33;1mWARNING: You have to wait for process $PID to finish\e[0m"
        $KIRA_SCRIPTS/progress-touch.sh "+0;$((6+$CONTAINERS_COUNT));48;$PID" 2> "$KIRA_DUMP/INFRA/progress.log" || echo -e "\nWARNING: Progress tool failed"
        FAILURE="False" && wait $PID || FAILURE="True"
        [ "$FAILURE" == "True" ] && echo "ERROR: Delete script failed, logs are available in the '$KIRA_DUMP' directory" && read -d'' -s -n1 -p 'Press any key to continue...'
        [ "$FAILURE" == "False" ] && echo -e "\nSUCCESS: Infra was wiped"
        break
    elif [ "${OPTION,,}" == "w" ] ; then
        echo "INFO: Please wait, refreshing user interface..." && break
    elif [ "${OPTION,,}" == "x" ] ; then
        exit 0
    fi
done

if [ -f $RESTART_SIGNAL ] ; then
   rm -f $RESTART_SIGNAL
else
    touch /tmp/rs_git_manager
    touch /tmp/rs_container_manager
fi

touch $LOOP_FILE && [ ! -z "$(cat $LOOP_FILE || echo '')" ] && sleep 2
source $KIRA_MANAGER/manager.sh

