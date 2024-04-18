#!/bin/bash
set -e

# build .deb package
INSTALLDIR=/usr/share/certuploader
BUILDDIR=certuploader

# check root permissions
if [ "$EUID" -ne 0 ] && ! groups | grep -q sudo ; then
	echo "Please run this script as root!"
	#exit 1 # disabled for github workflow. don't know why this check fails here but sudo works.
fi

# cd to working dir
cd "$(dirname "$0")"

# compile language files
make -C ../..

# empty / create necessary directories
if [ -d "$BUILDDIR/usr" ]; then
    sudo rm -r $BUILDDIR/usr
fi

# copy files in place
sudo install -D -m 644 ../../assets/*.png                             -t $BUILDDIR/usr/share/pixmaps
sudo install -D -m 644 ../../assets/certuploader.desktop              -t $BUILDDIR/usr/share/applications
sudo install -D -m 644 ../../assets/certuploader-check-expiry.desktop -t $BUILDDIR/etc/xdg/autostart
sudo install -D -m 644 ../../lang/*.qm                         -t $BUILDDIR/$INSTALLDIR/lang
sudo install -D -m 644 ../../certuploader/*.py                 -t $BUILDDIR/$INSTALLDIR/certuploader
sudo install -D -m 644 ../../requirements.txt                  -t $BUILDDIR/$INSTALLDIR
sudo install -D -m 644 ../../setup.py                          -t $BUILDDIR/$INSTALLDIR
sudo install -D -m 644 ../../README.md                         -t $BUILDDIR/$INSTALLDIR

# make binary available in PATH
sudo mkdir -p $BUILDDIR/usr/bin
sudo ln -sf   $INSTALLDIR/venv/bin/certuploader     $BUILDDIR/usr/bin/certuploader

# set file permissions
sudo chown -R root:root $BUILDDIR

# build deb
sudo dpkg-deb -Zxz --build $BUILDDIR

echo "Build finished"
