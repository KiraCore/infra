#!/bin/bash

exec 2>&1
set -e

# (rm -fv $KIRA_MANAGER/git-manager.sh) && nano $KIRA_MANAGER/git-manager.sh && chmod 777 $KIRA_MANAGER/git-manager.sh && touch /tmp/rs_git_manager

REPO_SSH=$1
REPO_HTTPS=$2
BRANCH=$3
DIRECTORY=$4
BRANCH_ENVAR=$5
EDITORS=$6

[ -z "$BRANCH_ENVAR" ] && echo "Git manager failure, BRANCH_ENVAR property was not defined" && exit 1
[ -z "$EDITORS" ] && EDITORS="code"

LOOP_FILE="/tmp/git_manager_loop"
RESTART_SIGNAL="/tmp/rs_git_manager"
source "/etc/profile" &> /dev/null

DEBUG_MODE=$7
if [ "$DEBUG_MODE" == "True" ] ; then set -x ; else set +x ; fi

while : ; do
    START_TIME="$(date -u +%s)"
    [ -f $RESTART_SIGNAL ] && break
    
    mkdir -p $DIRECTORY
    cd $DIRECTORY

    BRANCH_REF=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "$BRANCH")
    $(git remote set-url origin $REPO_HTTPS 2>/dev/null) || echo "WARNING: Failed to set origin of the remote branch"
    $(git fetch origin $BRANCH_REF --tags 2>/dev/null) || echo "WARNING: Failed to fetch remote changes"

    COMMIT_HASH=$(git log -n1 --pretty='%h' 2>/dev/null || echo "undefined")
    TAG=$(git describe --exact-match --tags $COMMIT_HASH 2>/dev/null || echo "")

    # Following command detects if upstream is specified and sets it if not
    $(git cherry &>/dev/null || git branch --set-upstream-to="origin/$BRANCH_REF" &>/dev/null) || echo "WARNING: Failed to set upstream origin"
    
    BEHIND=$(git rev-list $BRANCH_REF..origin/$BRANCH_REF --count || echo "unknown")
    BEHIND_INFO=$BEHIND
    [ "$BEHIND" == "0" ] && BEHIND_INFO="Local branch is up to date"
    [ -z "${BEHIND##[0-9]*}"  ] && [ $BEHIND -eq 1  ] && BEHIND_INFO="$BEHIND commit behind remote"
    [ -z "${BEHIND##[0-9]*}"  ] && [ $BEHIND -ge 2  ] && BEHIND_INFO="$BEHIND commits behind remote"

    CHANGES=$(git diff --shortstat || echo "unknown")
    CHANGES_INFO=$(echo $CHANGES | xargs) # remove whitespaces
    NOT_PUSHED=$(git cherry || echo "unknown") # not pushed changes
    [ ! -z "$NOT_PUSHED" ] && [ -z "$CHANGES_INFO" ] && CHANGES_INFO="Detected NOT pushed changes!"
    [ -z "$CHANGES_INFO" ] && CHANGES_INFO="NO changes detected"
    CHANGES_INFO=$(echo $CHANGES_INFO | sed s/" insertions"// | sed s/" deletions"//)

    CONFLICTS=$(git --no-pager diff --name-only --diff-filter=U | wc -l || echo "")
    UNRESOLVED_CONFLICTS=$(git diff --check | grep -i conflict | wc -l || echo "")
    [ "$CONFLICTS" != "0" ] && CHANGES_INFO="\e[31;1mDetected $CONFLICTS NOT COMMITED conflict/s\e[32;1m"
    [ "$UNRESOLVED_CONFLICTS" != "0" ] && CHANGES_INFO="\e[31;1mDetected $CONFLICTS UNRESOLVED conflict/s\e[32;1m"
    
    clear
    
    echo -e "\e[32;1m-------------------------------------------------"
    echo "|           KIRA GIT MANAGER v0.0.2             |"
    echo "|             $(date '+%d/%m/%Y %H:%M:%S')               |"
    echo "|-----------------------------------------------|"
    echo "|         SSH: $REPO_SSH"
    echo "|       HTTPS: $REPO_HTTPS"
    echo "|    Checkout: $BRANCH"
    echo "|   HEAD Name: $BRANCH_REF"
    echo "| Commit Hash: $COMMIT_HASH"
    [ ! -z "$TAG" ] && \
    echo "|  Branch Tag: $TAG"
    [ -z "$TAG" ] && \
    echo "|  Branch Tag: undefined"
    echo "|    Location: $DIRECTORY"
    echo "|    Position: $BEHIND_INFO"
 echo -e "|     Changes: $CHANGES_INFO"
    echo "|-----------------------------------------------|"
    if [[ $EDITORS == *"code"* ]]; then
        echo "| [V] | VIEW Repo in Code Editor                |"
    fi

    if [[ $EDITORS == *"goland"* ]]; then
        echo "| [G] | View Repo in GOLAND IDE                 |"
    fi
    
    [ "$UNRESOLVED_CONFLICTS" == "0" ] && [ ! -z "$CHANGES" ] && \
    echo "| [C] | COMMIT New Changes                      |" # only if there are changes
    [ ! -z "$NOT_PUSHED" ] && \
    echo "| [P] | PUSH New Changes to $BRANCH" # only push if not pushed commits found
    [ -z "$CHANGES" ] && [ ! -z "$BEHIND" ] && [ -z "${BEHIND##[0-9]*}" ] && [ $BEHIND -ge 1 ] && \
    echo "| [L] | Pull LATEST Changes                     |" # only pull if not up to date
    [ "$UNRESOLVED_CONFLICTS" != "0" ] && \
    echo "| [S] | SHOW Conflicts                          |"
    [ -z "$CHANGES" ] && [ -z "$NOT_PUSHED" ] && [ ! -z "$TAG" ] && \
    echo "| [T] | Change Branch TAG                       |"
    [ -z "$CHANGES" ] && [ -z "$NOT_PUSHED" ] && [ -z "$TAG" ] && \
    echo "| [T] | Create New Branch TAG                   |"
    echo "| [R] | Wipe and RESTORE Repo from Remote       |"
    echo "| [B] | Change to Diffrent Remote BRANCH        |"
    echo "| [N] | Create NEW Branch from Current Remote   |"
    [ ! -z "$BEHIND" ] && [ -z "${BEHIND##[0-9]*}" ] && [ $BEHIND -eq 0 ] && [ -z "$NOT_PUSHED" ] && [ -z "$CHANGES" ] && \
    echo "| [A] | Pull Changes from ANOTHER Branch        |"
    echo "|-----------------------------------------------|"
    echo "| [X] | Exit | [W] | Refresh Window | [Y] Debug |"
 echo -e "-------------------------------------------------\e[0m"

    echo -en "Input option then press [ENTER] or [SPACE]: " && rm -f $LOOP_FILE && touch $LOOP_FILE && OPTION=""
    while : ; do
        [ -f $LOOP_FILE ] && OPTION=$(cat $LOOP_FILE || echo "")
        [ -f $RESTART_SIGNAL ] && break
        [ -z "$OPTION" ] && [ $(($(date -u +%s)-$START_TIME)) -ge 6 ] && break
        read -n 1 -t 3 KEY || continue
        [ ! -z "$KEY" ] && echo "${OPTION}${KEY}" > $LOOP_FILE
        [ -z "$KEY" ] && break
    done
    OPTION=$(cat $LOOP_FILE || echo "") && [ -z "$OPTION" ] && continue
    ACCEPT="" && while [ "${ACCEPT,,}" != "y" ] && [ "${ACCEPT,,}" != "n" ] ; do echo -en "\e[36;1mPress [Y]es to confirm option (${OPTION^^}) or [N]o to cancel: \e[0m\c" && read  -d'' -s -n1 ACCEPT && echo "" ; done
    [ "${ACCEPT,,}" == "n" ] && echo -e "\nWARINIG: Operation was cancelled\n" && continue

    FAILED="False"
    if [ "${OPTION,,}" == "v" ] ; then
        echo "INFO: Starting code editor..."
        USER_DATA_DIR="/usr/code$DIRECTORY"
        rm -rf $USER_DATA_DIR
        mkdir -p $USER_DATA_DIR
        code --user-data-dir $USER_DATA_DIR $DIRECTORY
        continue
    elif [ "${OPTION,,}" == "g" ] ; then
        echo "INFO: Starting goland editor..."
        gnome-terminal -- script -e $KIRA_DUMP/INFRA/manager/git-goland-$BRANCH_ENVAR.log -c "goland $DIRECTORY ; read -d'' -s -n1 -p 'Press any key to exit...' && exit"
        continue
    elif [ "${OPTION,,}" == "c" ] ; then
        echo -e "\e[36;1mType desired commit message: \e[0m\c" && read COMMIT
        if [ -z "$COMMIT" ] ; then
            echo "WARINIG: Commit message was not set"
            FORCE="" && while [ "${FORCE,,}" != "y" ] && [ "${FORCE,,}" != "n" ] ; do echo -e "\n\e[36;1mPress [Y]es to commit empty message or [N]o to cancel: \e[0m\c" && read  -d'' -s -n1 FORCE ; done
            [ "${FORCE,,}" == "y" ] && COMMIT="Forced commit or minor changes"
            [ "${FORCE,,}" == "n" ] && echo "WARINIG: Commit was cancelled" && break
        fi
        echo "INFO: Commiting changes..."
        git add -A || FAILED="True"
        [ "$FAILED" == "False" ] && git commit -a -m "[$(date '+%d/%m/%Y %H:%M:%S')] $COMMIT" || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Commit failed" && break
        echo "SUCCESS: Commit suceeded"
        continue
    elif [ "${OPTION,,}" == "p" ] ; then
        echo "INFO: Pushing changes..."
        git checkout $BRANCH || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to checkout '$BRANCH'" && break

        git merge $BRANCH_REF || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to merge changes from '$NEW_BRANCH'" && break

        git remote set-url origin $REPO_SSH || FAILED="True"
        [ "$FAILED" == "False" ] && ssh-agent sh -c "ssh-add $SSH_KEY_PRIV_PATH ; git push origin $BRANCH" || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Push failed" && break
        
        echo "SUCCESS: Push suceeded"
        continue
    elif [ "${OPTION,,}" == "r" ] ; then
        $KIRA_SCRIPTS/git-pull.sh "$REPO_SSH" "$BRANCH" "$DIRECTORY" || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Pull failed" && break
        
        echo "SUCCESS: Pull suceeded"
        continue
    elif [ "${OPTION,,}" == "b" ] ; then
        echo "INFO: Listing available branches..."
        git branch -r || echo "ERROR: Failed to list remote branches"
        echo -e "\e[36;1mProvide name of EXISTING remote branch to checkout: \e[0m\c" && read NEW_BRANCH
        [ -z "$NEW_BRANCH" ] && echo "ERROR: Branch was not defined" && break
        [ "$NEW_BRANCH" == "$BRANCH" ] && echo "ERROR: Can't switch to branch with the same name" && break

        $KIRA_SCRIPTS/git-pull.sh "$REPO_SSH" "$NEW_BRANCH" "$DIRECTORY" || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Changing branch failed" && break

        BRANCH=$NEW_BRANCH
        CDHelper text lineswap --insert="$BRANCH_ENVAR=$BRANCH" --prefix="$BRANCH_ENVAR=" --path=$ETC_PROFILE --silent=$SILENT_MODE
        
        echo "SUCCESS: Changing branch suceeded"
        break
    elif [ "${OPTION,,}" == "n" ] ; then
        echo "INFO: Listing available branches..."
        git branch -r || echo "ERROR: Failed to list remote branches"
        git remote set-url origin $REPO_SSH || FAILED="True"
        [ -z "$FAILED" ] && echo "ERROR: Failed to set remote url for origin" && break

        echo -e "\e[36;1mProvide name of a NEW branch to create: \e[0m\c" && read NEW_BRANCH
        [ -z "$NEW_BRANCH" ] && echo "ERROR: Branch was not defined" && break
        [ "$NEW_BRANCH" == "$BRANCH_REF" ] && echo "ERROR: Can't create a new branch with the same name as current branch" && break

        git remote set-url origin $REPO_SSH || FAILED="True"
        [ "$FAILED" == "False" ] && ssh-agent sh -c "ssh-add $SSH_KEY_PRIV_PATH ; git checkout -b $NEW_BRANCH $BRANCH_REF" || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to create new branch '$NEW_BRANCH' from '$BRANCH_REF'" && break
        
        ssh-agent sh -c "ssh-add $SSH_KEY_PRIV_PATH ; git push origin $NEW_BRANCH" || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to push-create new branch" && break

        BRANCH=$NEW_BRANCH
        CDHelper text lineswap --insert="$BRANCH_ENVAR=$BRANCH" --prefix="$BRANCH_ENVAR=" --path=$ETC_PROFILE --silent=$SILENT_MODE
        
        echo "SUCCESS: New branch was created"
        break
    elif [ "${OPTION,,}" == "l" ] ; then
        git pull --no-edit origin $BRANCH_REF || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to pull chnages from origin to branch '$BRANCH_REF'" && break
        git merge origin $BRANCH_REF || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to merge chnages from origin to local branch '$BRANCH_REF'"
        break
    elif [ "${OPTION,,}" == "a" ] ; then
        echo "INFO: Listing available branches..."
        git branch -r || echo "ERROR: Failed to list remote branches"
        echo -e "\e[36;1mProvide name of EXISTING branch to get changes from: \e[0m\c" && read NEW_BRANCH
        [ -z "$NEW_BRANCH" ] && echo "ERROR: Branch was not defined" && break
        [ "$NEW_BRANCH" == "$BRANCH_REF" ] && echo "ERROR: Can't get changes from the same branch as local branch, use 'Pull LATEST Changes' option instead" && break

        git checkout $NEW_BRANCH || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to checkout '$NEW_BRANCH'" && break
        
        git pull --no-edit origin $NEW_BRANCH || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to pull chnages from origin to branch '$BRANCH_REF'" && break

        git checkout $BRANCH_REF || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to checkout '$BRANCH_REF'" && break

        git merge $NEW_BRANCH || FAILED="True"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to merge changes from '$NEW_BRANCH'" && break
        echo "SUCCESS: Changes from '$NEW_BRANCH' were merged into '$BRANCH_REF', you can now push them to remote"
        break
    elif [ "${OPTION,,}" == "s" ] ; then
        echo "INFO: List of files containg merge conflicts"
        echo -e "\e[31;1m"
        git diff --check | grep -i conflict || FAILED="True"
        echo -e "\e[39;0m"
        [ "$FAILED" == "True" ] && echo "ERROR: Failed to list merge conflicts" && break
        break
    elif [ "${OPTION,,}" == "t" ] ; then
        echo "INFO: Branch Tag setup..."
        echo -e "\e[36;1mInput new tag name: \e[0m\c" && read NEW_TAG
        CONFIRM="" && while [ "${CONFIRM,,}" != "y" ] && [ "${CONFIRM,,}" != "n" ] ; do echo -e "\n\e[36;1mPress [Y]es to assign tag '$NEW_TAG' to hash '$COMMIT_HASH' or [N]o to cancel: \e[0m\c" && read  -d'' -s -n1 CONFIRM ; done
        [ "${CONFIRM,,}" == "y" ] && echo "INFO: Tag '$NEW_TAG' was confirmed"
        [ "${CONFIRM,,}" == "n" ] && echo "WARINIG: Changing tag was cancelled" && break

        git remote set-url origin $REPO_SSH || FAILED="True"
        [ "$FAILED" == "True" ] && echo "WARNING: Failed to set ssh origin '$REPO_SSH'" && break
    
        if [ ! -z "$TAG" ] ; then
            git tag -d "$TAG" || echo "WARNING: Failed to delete LOCAL tag '$TAG'"
            ssh-agent sh -c "ssh-add $SSH_KEY_PRIV_PATH ; git push origin :refs/tags/$TAG" || echo "WARNING: Failed to delete old tag '$TAG'"
            echo "SUCCESS: Tag '$TAG' was deleted from the commit '$COMMIT_HASH'"
        else
            echo "INFO: Commit $COMMIT_HASH has no tags"
        fi
        
        FAILED="False"
        if [ ! -z "$NEW_TAG" ] ; then 
            git tag -d "$NEW_TAG" || echo "WARNING: Failed to delete LOCAL tag '$NEW_TAG'"
            ssh-agent sh -c "ssh-add $SSH_KEY_PRIV_PATH ; git push origin :refs/tags/$NEW_TAG" || echo "WARNING: Failed to delete REMOTE tag '$NEW_TAG'"
            ssh-agent sh -c "ssh-add $SSH_KEY_PRIV_PATH ; git tag \"$NEW_TAG\" \"$COMMIT_HASH\"" || FAILED="True"
            [ "$FAILED" == "True" ] && echo "ERROR: Failed to create new tag '$NEW_TAG'" && break
            
            ssh-agent sh -c "ssh-add $SSH_KEY_PRIV_PATH ; git push origin --tags" || FAILED="True"
            [ "$FAILED" == "True" ] && echo "ERROR: Failed to push tags" && break

            echo "SUCCESS: Tag '$NEW_TAG' was assigned to the commit '$COMMIT_HASH'"
        fi
        
        break
    elif [ "${OPTION,,}" == "w" ] ; then
        echo "INFO: Please wait, refreshing user interface..." && break
    elif [ "${OPTION,,}" == "y" ] ; then
        echo "INFO: Enabling debug mode..."
        DEBUG_MODE="True"
        break
    elif [ "${OPTION,,}" == "x" ] ; then
        exit 0
    fi
done

if [ -f $RESTART_SIGNAL ] ; then
   rm -f $RESTART_SIGNAL
else
    read -d'' -s -n1 -p 'Press any key to continue...'
    touch /tmp/rs_manager
    touch /tmp/rs_container_manager
fi

touch $LOOP_FILE && [ ! -z "$(cat $LOOP_FILE || echo '')" ] && sleep 3
source $KIRA_MANAGER/git-manager.sh "$REPO_SSH" "$REPO_HTTPS" "$BRANCH" "$DIRECTORY" "$BRANCH_ENVAR" "$EDITORS" "$DEBUG_MODE"
