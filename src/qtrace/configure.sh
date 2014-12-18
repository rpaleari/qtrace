#!/bin/bash

function show_help {
    echo
    echo "-=- QTrace configuration options -=-"
    echo
    echo "Syntax: $0 -a (x86|x64) [-t] [-u]"
    echo "Options:"
    echo " -a   Choose target architecture"
    echo " -p   Enable a specific QTrace plugin"
    echo " -t   Enable taint analysis"
    echo " -u   Use user-only target"
    echo
}

# Defaults
arch="x86"
plugin=""
b_taint=false
b_user=false

# Parse command-line options
while getopts ":a:p:tu" opt; do
    case $opt in
	a)
	    arch="$OPTARG"
	    ;;
	p)
	    plugin="$OPTARG"
	    ;;
	t)
	    b_taint=true
	    ;;
	u)
	    b_user=true
	    ;;
	:|\?)
	    show_help
	    exit 1
	    ;;
    esac
done

# Validate parameters
echo "[*] Architecture: $arch"
echo "[*] Taint analysis? $b_taint"
echo "[*] User-only? $b_user"
echo "[*] Plugin: $plugin"

opts=""

if $b_user ; then
    # User-only targets
    if [ "$arch" == "x86" ] ; then
	target="i386-linux-user"
    elif [ "$arch" == "x64" ] ; then
	target="x86_64-linux-user"
    else
	echo "[!] Unsupported user architecture $arch"
	exit 2
    fi
else
    # System-wide targets
    opts="$opts --disable-user"
    if [ "$arch" == "x86" ] ; then
	target="i386-softmmu"
    elif [ "$arch" == "x64" ] ; then
	target="x86_64-softmmu"
    else
	echo "[!] Unsupported system architecture $arch"
	exit 2
    fi
fi

# Disable taint-tracking
if ! $b_taint ; then
    opts="$opts --disable-qtrace-taint"
fi

# Select a plugin different from the default one
if [ "$plugin" != "" ] ; then
    opts="$opts --with-qtrace-plugin=$plugin"
fi

# Check for SDL
pkg-config sdl
has_sdl=$?

pkg-config sdl2
has_sdl2=$?

if [ "$has_sdl" == "0" ] || [ "$has_sdl2" == "0" ] ; then
    opts="$opts --enable-sdl"
fi

# All done, configure QEMU
./configure --target-list=$target --enable-vnc --disable-kvm \
    --disable-docs --disable-vhost-net --disable-vhost-scsi $opts

