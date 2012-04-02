#!/bin/bash - 
#===============================================================================
#
#          FILE:  test1.sh
# 
#         USAGE:  ./test1.sh 
# 
#   DESCRIPTION:  Simple test of green device mapper. 1) create a green virtual
#   device; 2) format the disk, mount and create a simple file; 3) umount and
#   then remount to test the file content just wrote.
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#         NOTES:  ---
#        AUTHOR: Ming Chen
#       COMPANY: mchen@cs.stonybrook.edu
#       CREATED: 04/02/2012 12:25:25 AM EDT
#      REVISION:  ---
#===============================================================================

set -o nounset                          # Treat unset variables as an error
set -o errexit                          # Stop script if command fail
export PATH="/bin:/usr/bin:$HOME/bin:/sbin"             
IFS=$' \t\n'                            # Reset IFS
unset -f unalias                        # Make sure unalias is not a function
\unalias -a                             # Unset all aliases
ulimit -H -c 0 --                       # disable core dump
hash -r                                 # Clear the command path hash

GREEN_HOME=/home/ming/cse595g3
MSG="Hello Green"
tmpfile=`mktemp`

cd $GREEN_HOME
insmod src/dm-green.ko
dmsetup create green1 src/test/green_conf_2.txt
mke2fs -t ext2 /dev/mapper/green1
mount /dev/mapper/green1 /mnt/green
echo "$MSG" > $tmpfile
cp $tmpfile /mnt/green/hello.txt

umount /mnt/green
dmsetup remove /dev/mapper/green1
dmsetup create green1 src/test/green_conf_2.txt
mount /dev/mapper/green1 /mnt/green
if diff -q $tmpfile /mnt/green/hello.txt; then
    echo "test succeed!"
    result=0
else
    echo "test failed!"
    result=1
fi

umount /mnt/green
dmsetup remove /dev/mapper/green1
rmmod src/dm-green.ko
rm -f $tmpfile
exit $result
