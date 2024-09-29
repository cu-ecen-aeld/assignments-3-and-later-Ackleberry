#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]; then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p "${OUTDIR}"

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
	# Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi

if [ ! -e "${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image" ]; then
	cd linux-stable
	echo "Checking out version ${KERNEL_VERSION}"
	git checkout ${KERNEL_VERSION}

	# TODO: Add your kernel build steps here
	make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper    # Deep clean, remove existing configs
	make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig   # Generate default config for arm64
	make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all     # Build everything needed
	make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules     # Build loadable kernel modules
	make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs        # build Device tree file
fi

echo "Adding the Image in outdir"
cp "${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image" "${OUTDIR}"

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]; then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
	sudo rm -rf "${OUTDIR}/rootfs"
fi

# Create necessary base directories
mkdir -p "${OUTDIR}/rootfs"
cd "${OUTDIR}/rootfs"
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]; then
	git clone git://busybox.net/busybox.git
	cd busybox
	git checkout ${BUSYBOX_VERSION}
	echo "Configuring BusyBox..."
	make distclean
	make defconfig
else
	cd busybox
fi

echo "Making and installing BusyBox..."
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX="${OUTDIR}/rootfs" ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Library dependencies"
${CROSS_COMPILE}readelf -a busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a busybox | grep "Shared library"

# Add library dependencies to rootfs
echo "Adding library dependencies to RootFS"
SYS_ROOT=$(${CROSS_COMPILE}gcc -print-sysroot)
cp "${SYS_ROOT}/lib/ld-linux-aarch64.so.1" "${OUTDIR}/rootfs/lib"
cp "${SYS_ROOT}/lib64/libm.so.6" "${OUTDIR}/rootfs/lib64"
cp "${SYS_ROOT}/lib64/libc.so.6" "${OUTDIR}/rootfs/lib64"
cp "${SYS_ROOT}/lib64/libresolv.so.2" "${OUTDIR}/rootfs/lib64"

echo "Making device nodes"
cd "${OUTDIR}/rootfs"
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 666 dev/ttyAMA0 c 1 5

echo "Cleaning and building writer utility"
cd "${FINDER_APP_DIR}"
make clean
make CROSS_COMPILE=${CROSS_COMPILE}

echo "Copying finder related scripts and executables to /home directory on target rootfs"
cp ./finder.sh ./finder-test.sh ./writer ./autorun-qemu.sh "${OUTDIR}/rootfs/home"
mkdir -p "${OUTDIR}/rootfs/home/conf"
cp ../conf/username.txt ../conf/assignment.txt "${OUTDIR}/rootfs/home/conf"
cp ../conf/username.txt ../conf/assignment.txt "${OUTDIR}/rootfs/home/conf"

echo "Chowning the root directory"
sudo chown root:root "${OUTDIR}/rootfs"

echo "Creating initramfs.cpio.gz"
cd "${OUTDIR}/rootfs"
find . | cpio -H newc -ov --owner root:root > "${OUTDIR}/initramfs.cpio"
gzip -f "${OUTDIR}/initramfs.cpio"
