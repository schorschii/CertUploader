#!/bin/bash
set -e

# build .deb package

# check root permissions
if [ "$EUID" -ne 0 ]
	then echo "Please run this script as root!"
	exit
fi

# cd to working dir
cd "$(dirname "$0")"

# compile language files
lrelease ../../lang/*.ts

# empty / create necessary directories
mkdir -p certuploader/usr/bin
mkdir -p certuploader/usr/share/certuploader/lang
mkdir -p certuploader/usr/share/pixmaps
mkdir -p certuploader/usr/share/applications
mkdir -p certuploader/etc/xdg/autostart

# copy files in place
cp ../../certuploader.py certuploader/usr/bin/certuploader
cp ../../lang/*.qm certuploader/usr/share/certuploader/lang
cp ../../assets/*.png certuploader/usr/share/pixmaps
cp ../../assets/certuploader.desktop certuploader/usr/share/applications
cp ../../assets/certuploader-check-expiry.desktop certuploader/etc/xdg/autostart

# set file permissions
chown -R root:root certuploader
chmod 775 certuploader/usr/bin/certuploader

# build deb
dpkg-deb -Zxz --build certuploader

echo "Build finished"
