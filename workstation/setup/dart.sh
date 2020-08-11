
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

FLUTTER_VERSION="v1.16.3"
FLUTTER_REMOTE="https://github.com/flutter/flutter"

SETUP_CHECK="$KIRA_SETUP/dart-v0.0.1-$FLUTTER_VERSION"
if [ ! -f "$SETUP_CHECK" ] ; then
    echo "INFO: Intalling Dart..."
    apt-get install dart -y
    echo "INFO: Intalling Android Studio..."
    apt-get install android-studio -y
    apt install default-jdk -y
    snap install androidsdk
    yes | androidsdk "platforms;android-28" "build-tools;28.0.3"
    echo "INFO: Intalling Flutter..."
    $KIRA_SCRIPTS/git-pull.sh "$FLUTTER_REMOTE" "$FLUTTER_VERSION" "$FLUTTERROOT"
    cd $FLUTTERROOT
    git remote get-url origin
    flutter channel stable || echo "Failed to checkout flutter stable"
    flutter upgrade || echo "Failed to upgrade flutter"
    flutter --version
    flutter config --no-analytics
    flutter config --enable-web
    flutter doctor
    touch $SETUP_CHECK
else
    dart --version
    echo "INFO: Dart was already installed"
    flutter --version
    echo "INFO: Flutter was already installed"
    androidsdk --version
    echo "INFO: Android SDK was already installed"
fi
