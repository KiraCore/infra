
#!/bin/bash

exec 2>&1
set -e

ETC_PROFILE="/etc/profile"
source $ETC_PROFILE &> /dev/null

KIRA_SETUP_BASE_TOOLS="$KIRA_SETUP/base-tools-v0.0.8" 
if [ ! -f "$KIRA_SETUP_BASE_TOOLS" ] ; then
    echo "INFO: Update and Intall basic tools and dependencies..."
    apt-get update -y --fix-missing
    apt-get install -y --allow-unauthenticated --allow-downgrades --allow-remove-essential --allow-change-held-packages \
        aptitude \
        autoconf \
        automake \
        apt-utils \
        awscli \
        dconf-editor \
        default-jre \
        build-essential \
        bind9-host \
        bzip2 \
        coreutils \
        clang \
        cmake \
        dnsutils \
        dpkg-dev \
        ed \
        expect \
        file \
        gcc \
        gdebi \
        g++ \
        git \
        gnupg2 \
        groff \
        htop \
        hashdeep \
        hxtools \
        ifupdown \
        imagemagick \
        iputils-tracepath \
        iputils-ping \
        jq \
        language-pack-en \
        libtool \
        libzip4 \
        libssl1.1 \
        libudev-dev \
        libunwind-dev \
        libusb-1.0-0-dev \
        locales \
        make \
        nano \
        nautilus-admin \
        nginx \
        netbase \
        netcat-openbsd \
        net-tools \
        nodejs \
        node-gyp \
        pkg-config \
        python \
        patch \
        procps \
        python3 \
        python3-pip \
        rename \
        rsync \
        snapd \
        socat \
        software-properties-common \
        stunnel \
        subversion \
        syslinux \
        tar \
        telnet \
        tzdata \
        wipe \
        xdotool \
        xz-utils \
        yarn \
        zip

    # https://linuxhint.com/install_aws_cli_ubuntu/
    aws --version
    touch $KIRA_SETUP_BASE_TOOLS

    #allow to execute scripts just like .exe files with double click
    gsettings set org.gnome.nautilus.preferences executable-text-activation 'launch'
else
    echo "INFO: Base tools were already installed."
fi
