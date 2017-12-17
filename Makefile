#
#
#make custom lib , rom
#
#

srcroot=/home/fhc/ext800/src-android-local/android-4.4.4_r1

#VPATH=$(dvmsrcpath)
vpath %.so $(srcroot)/out/target/product/hammerhead/system/lib
vpath %.cpp $(srcroot)/dalvik/vm/oo:$(srcroot)/dalvik/vm/native

libdvm_t.so:libdvm.so
	cp $(srcroot)/out/target/product/hammerhead/system/lib/libdvm.so libdvm_t.so

libdvm.so:Class.cpp dalvik_system_DexFile.cpp
	 androot=$(srcroot) ./builddvm.sh
Class.cpp:u_Class.cpp
	cp u_Class.cpp $(srcroot)/dalvik/vm/oo/Class.cpp
dalvik_system_DexFile.cpp:u_dalvik_system_DexFile.cpp
	cp u_dalvik_system_DexFile.cpp $(srcroot)/dalvik/vm/native/dalvik_system_DexFile.cpp

clean:
	rm $(srcroot)/out/target/product/hammerhead/system/lib/libdvm.so libdvm_t.so
install:
	adb push libdvm_t.so /data/local/tmp/
	adb shell su -c mount -o rw,remount /system
	adb shell su -c cp /data/local/tmp/libdvm_t.so /system/lib/libdvm.so
	adb shell su -c mount -o ro,remount /system
uninstall:
	adb push libdvm_ori.so /data/local/tmp/
	adb shell su -c mount -o rw,remount /system
	adb shell su -c cp /data/local/tmp/libdvm_ori.so /system/lib/libdvm.so
	adb shell su -c mount -o ro,remount /system
