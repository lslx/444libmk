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
