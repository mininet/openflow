#!/bin/bash
set -o errexit
set -o nounset

# if user specifies a folder, cd to it
if [ $# -ne 0 ]; then
    cd $1
fi

# sanity check: make sure script is running from within the plugin build directory
origdir=`pwd`
topdir=wireshark_dissectors
if [ "$topdir" != `dirname $origdir | sed -e "s#.*/##"` ]; then
    echo "Error: script must be run from within the plugin's subdirectory with $topdir"
    exit 1
fi

# sanity check: make sure build works
rm -f *.so
make > /dev/null 2> /dev/null
plugin=`grep 'PLUGIN_NAME =' Makefile | sed -e "s#PLUGIN_NAME =##" -e "s# ##g"`.so
if [ ! -f $plugin ]; then
    echo "Error: make failed to build $plugin"
    exit 1
fi

# make a temporary folder for the build file
tmpdir=/tmp/.$$
builddir="$tmpdir/$topdir/openflow"
mkdir $tmpdir

# copy the wireshark plugin directory to the temp folder
cp -r ../ "$tmpdir/$topdir"

# add the openflow header to the build folder which is in the include search path
cp ../../../include/openflow/openflow.h "$builddir/"

# cleanup the contents of the build folder
cd "$builddir"
make clean
rm -f *.tgz $0

# get the version of the plugin
version=`grep '#define VERSION' moduleinfo.h | cut -d\" -f2`

# replace <DATE> tag in README with date information'
date=`date`
cat ../README | sed -e "s#<VERSION>#Plugin Version: $version#g" > ../tmp
cat ../tmp | sed -e "s#<DATE>#Distribution Creation Date: $date#g" > ../README

# make a tarball from the build folder
tarball="openflow-wireshark-dissector-v$version.tar.gz"
cd ../../
tar -zcf "$tarball" "$topdir"

# put the tarball back in the original directory
mv "$tarball" "$origdir/"

# cleanup the temporary folder
rm -rf "$tmpdir"

# tell the user what we created
echo "tarballed release is now ready: $tarball"
