#!/bin/bash
#
# Author: Frédéric Pierret (https://github.com/fepitre)
#
#   Script for generating a kickstarted CentOS 7 ISO
#

[[ VERBOSE -ge 2 ]] && set -x

[[ "x$VERBOSE" == "x" ]] && VERBOSE=0

set -e

if ! [ -e /etc/centos-release ]; then
    echo "Unsupported distro"
    exit 1
fi

DEPENDENCIES="rsync wget genisoimage yum-utils syslinux fuse fuseiso createrepo"
for rpm in $DEPENDENCIES
do
    if ! rpm -q "$rpm" > /dev/null 2>&1; then
        echo "Please install $rpm:"
        echo "    yum install $rpm"
        echo "Needed dependencies: $DEPENDENCIES"
        exit 1
    fi
done

# Info
HELP="You can use script with arguments

OPTIONS:
    --help          This help
    --kickstart     Kickstart file
    --destdir       Destination directory
    --sourceiso     Source ISO to used
"

exit_builder() {
    local exit_code=$?

    # Clean
    fusermount -u "$MOUNTDIR" || true
    rm -rf "$TMPDIR"

    exit "${exit_code}"
}

echo_verb() {
    if [[ VERBOSE -ge 1 ]]; then
        echo "$@"
    fi
}

# Command line parameters
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kickstart)
            if [[ -z $2 || ! -e "$(readlink -f "$2")" ]]; then
                echo "Please provide a kickstart file"
            else
                KICKSTART="$(readlink -f "$2")"
            fi
            ;;
        --sourceiso)
            if [[ -z $2 || ! -e "$(readlink -f "$2")" ]]; then
                echo "Please provide an existing CentOS iso"
            else
                CENTOS_ISO_MINIMAL="$(readlink -f "$2")"
            fi
            ;;
        --destdir)
            if [[ -z $2 ]]; then
                echo "Please provide a destination directory"
            else
                DESTDIR="$(readlink -f "$2")"
            fi
            ;;
        --help)
            echo -e "$HELP"
            exit
            ;;
    esac
    shift
done

# Local variables
LOCALDIR="$(readlink -f "$(dirname "$0")")"
TMPDIR="$(mktemp -d -p "$LOCALDIR")"
MOUNTDIR="$TMPDIR/mnt"
ISODIR="$TMPDIR/iso"
LOGDIR="$LOCALDIR/log"

[[ "x$KICKSTART" == "x" ]] && { echo "Please provide a kickstart file"; exit 1; }
[[ "x$DESTDIR" == "x" ]] && DESTDIR="$TMPDIR"

CENTOS_ISO="CentOS-7-x86_64-$(basename "$KICKSTART"  | sed 's/\.ks//')"
LOGFILE="$LOGDIR/$(basename "$KICKSTART"  | sed 's/\.ks//')-$(date +%FT%H-%m-%S).log"

trap 'exit_builder' 0 1 2 3 6 15

# ---------------------------------------------------------------------#
# Generating custom ISO
# ---------------------------------------------------------------------#
echo_verb "-> Generating CentOS iso from kickstart $KICKSTART..."
## Create necessary directories
mkdir -p "$TMPDIR" "$MOUNTDIR" "$ISODIR" "$LOGDIR" "$DESTDIR"

## Download minimal iso
if [ "x$CENTOS_ISO_MINIMAL" == "x" ]; then
    echo_verb "--> Downloading CentOS minimal ISO..."
#    CENTOS_ISO_MINIMAL="https://buildlogs.centos.org/rolling/7/isos/x86_64/CentOS-7-x86_64-Minimal.iso"
    CENTOS_ISO_MINIMAL="http://centos.crazyfrogs.org/7.7.1908/isos/x86_64/CentOS-7-x86_64-Minimal-1908.iso"
    wget -q -c -O "$TMPDIR/CentOS-7-x86_64-Minimal.iso" "$CENTOS_ISO_MINIMAL"
    CENTOS_ISO_MINIMAL="$TMPDIR/CentOS-7-x86_64-Minimal.iso"
fi

## Mount image
echo_verb "--> Mounting CentOS minimal ISO..."
fuseiso "$CENTOS_ISO_MINIMAL" "$MOUNTDIR"

## Getting files from ISO
echo_verb "--> Getting files from ISO..."
rsync --exclude '*.rpm' --exclude 'repodata' -a "$MOUNTDIR"/* "$ISODIR"

## Create kickstart folder
mkdir -p "$ISODIR/ks"
cp "$KICKSTART" "$ISODIR/ks/ks.cfg"

## Create local repository
echo_verb "--> Creating local rpm repository..."
PACKAGES="$(sed -n '/%packages/,/%end/p;/%end/q' "$ISODIR/ks/ks.cfg" | sed '1d; /%end/d' | sed 's/\#.*//g; s/[[:blank:]]*//g; s/^-/--exclude=/g' | tr '\n' ' ')"
yumdownloader --disablerepo=* --enablerepo=base,updates,extras,epel \
    @anaconda-tools @base \
    $PACKAGES --releasever=7 \
    --resolv -x \*i686 --arch=x86_64 \
    --installroot="$ISODIR/Packages" \
    --destdir="$ISODIR/Packages" > "$LOGFILE" 2>&1
cp "$MOUNTDIR/repodata/"*c7-minimal-x86_64-comps.xml "$ISODIR/comps.xml"
rm -rf "$ISODIR/Packages/var"
cd "$ISODIR" && createrepo -g comps.xml . > "$LOGFILE" 2>&1

## Grub modifications
echo_verb "--> Modifying GRUB..."
sed -i 's#append initrd=initrd.img#append initrd=initrd.img inst.ks=hd:LABEL=CentOS\\x207\\x20x86_64:/ks/ks.cfg#g' "$ISODIR/isolinux/isolinux.cfg"
sed -i 's#timeout 600#timeout 30#g' "$ISODIR/isolinux/isolinux.cfg"
sed -i 's#inst.stage2#inst.ks=hd:LABEL=CentOS\\x207\\x20x86_64:/ks/ks.cfg inst.stage2#g' "$ISODIR/EFI/BOOT/grub.cfg"
sed -i '/menu default/d' "$ISODIR/isolinux/isolinux.cfg"
sed -i '/menu label ^Install CentOS 7/a \ \ menu default' "$ISODIR/isolinux/isolinux.cfg"
sed -i "s#CentOS 7#CentOS 7 $SPIN_NAME#g" "$ISODIR/isolinux/isolinux.cfg" "$ISODIR/EFI/BOOT/grub.cfg"

## Generate the final iso
echo_verb "--> Building custom iso..."
rm -rf "$DESTDIR/$CENTOS_ISO.iso"
mkisofs -o "$DESTDIR/$CENTOS_ISO.iso" \
    -b isolinux/isolinux.bin \
    -c isolinux/boot.cat \
    -no-emul-boot \
    -V 'CentOS 7 x86_64' \
    -boot-load-size 4 \
    -boot-info-table \
    -eltorito-alt-boot \
    -e images/efiboot.img \
    -no-emul-boot -R -J -v \
    -T "$ISODIR" > "$LOGFILE" 2>&1

isohybrid --uefi "$DESTDIR/$CENTOS_ISO.iso" > "$LOGFILE" 2>&1
