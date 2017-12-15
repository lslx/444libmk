#!/bin/bash
# build libdvm.so
source ~/.bash_profile_port
echo androot: $androot
patchpath=$MAIN_DATA_ROOT/importantbk



if ! (make -v | sed -n 1p | grep 3.81 );then
        sudo dpkg -i $patchpath/make_3.81-8.2ubuntu3_amd64.deb
fi
if ! (make -v | sed -n 1p | grep 3.81);then
        echo error info:  make version 
        return 1
fi
cd $androot
source build/envsetup.sh
lunch aosp_hammerhead-userdebug
cd dalvik/vm/native
mm

