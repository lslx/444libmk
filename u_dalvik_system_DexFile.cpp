/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * dalvik.system.DexFile
 */
#include "Dalvik.h"
#include "native/InternalNativePriv.h"

/*
 * Return true if the given name ends with ".dex".
 */
static bool hasDexExtension(const char* name) {
    size_t len = strlen(name);

    return (len >= 5)
        && (name[len - 5] != '/')
        && (strcmp(&name[len - 4], ".dex") == 0);
}

/*
 * Internal struct for managing DexFile.
 */
struct DexOrJar {
    char*       fileName;
    bool        isDex;
    bool        okayToFree;
    RawDexFile* pRawDexFile;
    JarFile*    pJarFile;
    u1*         pDexMemory; // malloc()ed memory, if any
};

/*
 * (This is a dvmHashTableFree callback.)
 */
void dvmFreeDexOrJar(void* vptr)
{
    DexOrJar* pDexOrJar = (DexOrJar*) vptr;

    ALOGV("Freeing DexOrJar '%s'", pDexOrJar->fileName);

    if (pDexOrJar->isDex)
        dvmRawDexFileFree(pDexOrJar->pRawDexFile);
    else
        dvmJarFileFree(pDexOrJar->pJarFile);
    free(pDexOrJar->fileName);
    free(pDexOrJar->pDexMemory);
    free(pDexOrJar);
}

/*
 * (This is a dvmHashTableLookup compare func.)
 *
 * Args are DexOrJar*.
 */
static int hashcmpDexOrJar(const void* tableVal, const void* newVal)
{
    return (int) newVal - (int) tableVal;
}

/*
 * Verify that the "cookie" is a DEX file we opened.
 *
 * Expects that the hash table will be *unlocked* here.
 *
 * If the cookie is invalid, we throw an exception and return "false".
 */
static bool validateCookie(int cookie)
{
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;

    LOGVV("+++ dex verifying cookie %p", pDexOrJar);

    if (pDexOrJar == NULL)
        return false;

    u4 hash = cookie;
    dvmHashTableLock(gDvm.userDexFiles);
    void* result = dvmHashTableLookup(gDvm.userDexFiles, hash, pDexOrJar,
                hashcmpDexOrJar, false);
    dvmHashTableUnlock(gDvm.userDexFiles);
    if (result == NULL) {
        dvmThrowRuntimeException("invalid DexFile cookie");
        return false;
    }

    return true;
}


/*
 * Add given DexOrJar to the hash table of user-loaded dex files.
 */
static void addToDexFileTable(DexOrJar* pDexOrJar) {
    /*
     * Later on, we will receive this pointer as an argument and need
     * to find it in the hash table without knowing if it's valid or
     * not, which means we can't compute a hash value from anything
     * inside DexOrJar. We don't share DexOrJar structs when the same
     * file is opened multiple times, so we can just use the low 32
     * bits of the pointer as the hash.
     */
    u4 hash = (u4) pDexOrJar;
    void* result;

    dvmHashTableLock(gDvm.userDexFiles);
    result = dvmHashTableLookup(gDvm.userDexFiles, hash, pDexOrJar,
            hashcmpDexOrJar, true);
    dvmHashTableUnlock(gDvm.userDexFiles);

    if (result != pDexOrJar) {
        ALOGE("Pointer has already been added?");
        dvmAbort();
    }

    pDexOrJar->okayToFree = true;
}

/*
 * private static int openDexFileNative(String sourceName, String outputName,
 *     int flags) throws IOException
 *
 * Open a DEX file, returning a pointer to our internal data structure.
 *
 * "sourceName" should point to the "source" jar or DEX file.
 *
 * If "outputName" is NULL, the DEX code will automatically find the
 * "optimized" version in the cache directory, creating it if necessary.
 * If it's non-NULL, the specified file will be used instead.
 *
 * TODO: at present we will happily open the same file more than once.
 * To optimize this away we could search for existing entries in the hash
 * table and refCount them.  Requires atomic ops or adding "synchronized"
 * to the non-native code that calls here.
 *
 * TODO: should be using "long" for a pointer.
 */
static void Dalvik_dalvik_system_DexFile_openDexFileNative(const u4* args,
    JValue* pResult)
{
    StringObject* sourceNameObj = (StringObject*) args[0];
    StringObject* outputNameObj = (StringObject*) args[1];
    DexOrJar* pDexOrJar = NULL;
    JarFile* pJarFile;
    RawDexFile* pRawDexFile;
    char* sourceName;
    char* outputName;

    if (sourceNameObj == NULL) {
        dvmThrowNullPointerException("sourceName == null");
        RETURN_VOID();
    }

    sourceName = dvmCreateCstrFromString(sourceNameObj);
    if (outputNameObj != NULL)
        outputName = dvmCreateCstrFromString(outputNameObj);
    else
        outputName = NULL;

    /*
     * We have to deal with the possibility that somebody might try to
     * open one of our bootstrap class DEX files.  The set of dependencies
     * will be different, and hence the results of optimization might be
     * different, which means we'd actually need to have two versions of
     * the optimized DEX: one that only knows about part of the boot class
     * path, and one that knows about everything in it.  The latter might
     * optimize field/method accesses based on a class that appeared later
     * in the class path.
     *
     * We can't let the user-defined class loader open it and start using
     * the classes, since the optimized form of the code skips some of
     * the method and field resolution that we would ordinarily do, and
     * we'd have the wrong semantics.
     *
     * We have to reject attempts to manually open a DEX file from the boot
     * class path.  The easiest way to do this is by filename, which works
     * out because variations in name (e.g. "/system/framework/./ext.jar")
     * result in us hitting a different dalvik-cache entry.  It's also fine
     * if the caller specifies their own output file.
     */
    if (dvmClassPathContains(gDvm.bootClassPath, sourceName)) {
        ALOGW("Refusing to reopen boot DEX '%s'", sourceName);
        dvmThrowIOException(
            "Re-opening BOOTCLASSPATH DEX files is not allowed");
        free(sourceName);
        free(outputName);
        RETURN_VOID();
    }

    /*
     * Try to open it directly as a DEX if the name ends with ".dex".
     * If that fails (or isn't tried in the first place), try it as a
     * Zip with a "classes.dex" inside.
     */
    if (hasDexExtension(sourceName)
            && dvmRawDexFileOpen(sourceName, outputName, &pRawDexFile, false) == 0) {
        ALOGV("Opening DEX file '%s' (DEX)", sourceName);

        pDexOrJar = (DexOrJar*) malloc(sizeof(DexOrJar));
        pDexOrJar->isDex = true;
        pDexOrJar->pRawDexFile = pRawDexFile;
        pDexOrJar->pDexMemory = NULL;
    } else if (dvmJarFileOpen(sourceName, outputName, &pJarFile, false) == 0) {
        ALOGV("Opening DEX file '%s' (Jar)", sourceName);

        pDexOrJar = (DexOrJar*) malloc(sizeof(DexOrJar));
        pDexOrJar->isDex = false;
        pDexOrJar->pJarFile = pJarFile;
        pDexOrJar->pDexMemory = NULL;
    } else {
        ALOGV("Unable to open DEX file '%s'", sourceName);
        dvmThrowIOException("unable to open DEX file");
    }

    if (pDexOrJar != NULL) {
        pDexOrJar->fileName = sourceName;
        addToDexFileTable(pDexOrJar);
    } else {
        free(sourceName);
    }

    free(outputName);
    RETURN_PTR(pDexOrJar);
}

/*
 * private static int openDexFile(byte[] fileContents) throws IOException
 *
 * Open a DEX file represented in a byte[], returning a pointer to our
 * internal data structure.
 *
 * The system will only perform "essential" optimizations on the given file.
 *
 * TODO: should be using "long" for a pointer.
 */
static void Dalvik_dalvik_system_DexFile_openDexFile_bytearray(const u4* args,
    JValue* pResult)
{
    ArrayObject* fileContentsObj = (ArrayObject*) args[0];
    u4 length;
    u1* pBytes;
    RawDexFile* pRawDexFile;
    DexOrJar* pDexOrJar = NULL;

    if (fileContentsObj == NULL) {
        dvmThrowNullPointerException("fileContents == null");
        RETURN_VOID();
    }

    /* TODO: Avoid making a copy of the array. (note array *is* modified) */
    length = fileContentsObj->length;
    pBytes = (u1*) malloc(length);

    if (pBytes == NULL) {
        dvmThrowRuntimeException("unable to allocate DEX memory");
        RETURN_VOID();
    }

    memcpy(pBytes, fileContentsObj->contents, length);

    if (dvmRawDexFileOpenArray(pBytes, length, &pRawDexFile) != 0) {
        ALOGV("Unable to open in-memory DEX file");
        free(pBytes);
        dvmThrowRuntimeException("unable to open in-memory DEX file");
        RETURN_VOID();
    }

    ALOGV("Opening in-memory DEX");
    pDexOrJar = (DexOrJar*) malloc(sizeof(DexOrJar));
    pDexOrJar->isDex = true;
    pDexOrJar->pRawDexFile = pRawDexFile;
    pDexOrJar->pDexMemory = pBytes;
    pDexOrJar->fileName = strdup("<memory>"); // Needs to be free()able.
    addToDexFileTable(pDexOrJar);

    RETURN_PTR(pDexOrJar);
}

/*
 * private static void closeDexFile(int cookie)
 *
 * Release resources associated with a user-loaded DEX file.
 */
static void Dalvik_dalvik_system_DexFile_closeDexFile(const u4* args,
    JValue* pResult)
{
    int cookie = args[0];
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;

    if (pDexOrJar == NULL)
        RETURN_VOID();
    if (!validateCookie(cookie))
        RETURN_VOID();

    ALOGV("Closing DEX file %p (%s)", pDexOrJar, pDexOrJar->fileName);

    /*
     * We can't just free arbitrary DEX files because they have bits and
     * pieces of loaded classes.  The only exception to this rule is if
     * they were never used to load classes.
     *
     * If we can't free them here, dvmInternalNativeShutdown() will free
     * them when the VM shuts down.
     */
    if (pDexOrJar->okayToFree) {
        u4 hash = (u4) pDexOrJar;
        dvmHashTableLock(gDvm.userDexFiles);
        if (!dvmHashTableRemove(gDvm.userDexFiles, hash, pDexOrJar)) {
            ALOGW("WARNING: could not remove '%s' from DEX hash table",
                pDexOrJar->fileName);
        }
        dvmHashTableUnlock(gDvm.userDexFiles);
        ALOGV("+++ freeing DexFile '%s' resources", pDexOrJar->fileName);
        dvmFreeDexOrJar(pDexOrJar);
    } else {
        ALOGV("+++ NOT freeing DexFile '%s' resources", pDexOrJar->fileName);
    }

    RETURN_VOID();
}

//------------------------added begin----------------------//

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "libdex/DexClass.h"

int get_pack_name(char *pack_name) {
	char cmdline_path[256] = {0};
	sprintf(cmdline_path, "/proc/%d/cmdline", getpid());
	int fd_cmdline = open(cmdline_path, O_RDONLY);
	if(fd_cmdline) {
		read(fd_cmdline, pack_name, 256);
		close(fd_cmdline);
		char* p = strchr(pack_name, ':');
		if(p) {
			*p = '_';
		}
		return 0;
	}
	return -1;
}

int get_dump_path(char *dump_path, int cookie) {
	char pack_name[256]={0};
	DexOrJar* pDexOrJar = (DexOrJar*)cookie;
	if(0 == get_pack_name(pack_name)) {
		sprintf(dump_path, "/data/local/tmp/%s", pack_name);
		if(0 != access(dump_path, F_OK)) {
			mkdir(dump_path, S_IRWXU|S_IRWXG|S_IRWXO);
		}
		char *ptr = strrchr(pDexOrJar->fileName, '/');
		if(ptr) {
			strcat(dump_path, ptr);
		}
		else {
			strcat(dump_path, "/");
			strcat(dump_path, "sb"/*pDexOrJar->fileName*/);
		}
		sprintf(dump_path, "%s_0x%08x/", dump_path, cookie);
		if(0 != access(dump_path, F_OK)) {
			mkdir(dump_path, S_IRWXU|S_IRWXG|S_IRWXO);
			return 0;
		}
	}
	return -1;
}

void write_log(char *dump_path, char *log_info) {
	char log_path[512] = {0};
	strcpy(log_path, dump_path);
	strcat(log_path, "debug_log.txt");
	int fd_log = open(log_path, O_RDWR|O_CREAT|O_APPEND, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd_log) {
		write(fd_log, log_info, strlen(log_info));
		close(fd_log);
	}
	return;
}

void writeLeb128(uint8_t ** ptr, uint32_t data)
{
    while (true) {
        uint8_t out = data & 0x7f;
        if (out != data) {
            *(*ptr)++ = out | 0x80;
            data >>= 7;
        } else {
            *(*ptr)++ = out;
            break;
        }
    }
}

void ReadClassDataHeader(const uint8_t** pData, DexClassDataHeader *pHeader) {
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}

void ReadClassDataField(const uint8_t** pData, DexField* pField) {
    pField->fieldIdx = readUnsignedLeb128(pData);
    pField->accessFlags = readUnsignedLeb128(pData);
}

void ReadClassDataMethod(const uint8_t** pData, DexMethod* pMethod) {
    pMethod->methodIdx = readUnsignedLeb128(pData);
    pMethod->accessFlags = readUnsignedLeb128(pData);
    pMethod->codeOff = readUnsignedLeb128(pData);
}

DexClassData* ReadClassData(const uint8_t** pData) {

    DexClassDataHeader header;

    if (*pData == NULL) {
        return NULL;
    }

    ReadClassDataHeader(pData,&header);

    size_t resultSize = sizeof(DexClassData) + (header.staticFieldsSize * sizeof(DexField)) + (header.instanceFieldsSize * sizeof(DexField)) + (header.directMethodsSize * sizeof(DexMethod)) + (header.virtualMethodsSize * sizeof(DexMethod));

    DexClassData* result = (DexClassData*) malloc(resultSize);

    if (result == NULL) {
        return NULL;
    }

    uint8_t* ptr = ((uint8_t*) result) + sizeof(DexClassData);

    result->header = header;

    if (header.staticFieldsSize != 0) {
        result->staticFields = (DexField*) ptr;
        ptr += header.staticFieldsSize * sizeof(DexField);
    } else {
        result->staticFields = NULL;
    }

    if (header.instanceFieldsSize != 0) {
        result->instanceFields = (DexField*) ptr;
        ptr += header.instanceFieldsSize * sizeof(DexField);
    } else {
        result->instanceFields = NULL;
    }

    if (header.directMethodsSize != 0) {
        result->directMethods = (DexMethod*) ptr;
        ptr += header.directMethodsSize * sizeof(DexMethod);
    } else {
        result->directMethods = NULL;
    }

    if (header.virtualMethodsSize != 0) {
        result->virtualMethods = (DexMethod*) ptr;
    } else {
        result->virtualMethods = NULL;
    }

    for (uint32_t i = 0; i < header.staticFieldsSize; i++) {
        ReadClassDataField(pData, &result->staticFields[i]);
    }

    for (uint32_t i = 0; i < header.instanceFieldsSize; i++) {
        ReadClassDataField(pData, &result->instanceFields[i]);
    }

    for (uint32_t i = 0; i < header.directMethodsSize; i++) {
        ReadClassDataMethod(pData, &result->directMethods[i]);
    }

    for (uint32_t i = 0; i < header.virtualMethodsSize; i++) {
        ReadClassDataMethod(pData, &result->virtualMethods[i]);
    }

    return result;
}

uint8_t* EncodeClassData(DexClassData *pData, int& len)
{
    len=0;

    len+=unsignedLeb128Size(pData->header.staticFieldsSize);
    len+=unsignedLeb128Size(pData->header.instanceFieldsSize);
    len+=unsignedLeb128Size(pData->header.directMethodsSize);
    len+=unsignedLeb128Size(pData->header.virtualMethodsSize);

    if (pData->staticFields) {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++) {
            len+=unsignedLeb128Size(pData->staticFields[i].fieldIdx);
            len+=unsignedLeb128Size(pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields) {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++) {
            len+=unsignedLeb128Size(pData->instanceFields[i].fieldIdx);
            len+=unsignedLeb128Size(pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods) {
        for (uint32_t i=0; i<pData->header.directMethodsSize; i++) {
            len+=unsignedLeb128Size(pData->directMethods[i].methodIdx);
            len+=unsignedLeb128Size(pData->directMethods[i].accessFlags);
            len+=unsignedLeb128Size(pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods) {
        for (uint32_t i=0; i<pData->header.virtualMethodsSize; i++) {
            len+=unsignedLeb128Size(pData->virtualMethods[i].methodIdx);
            len+=unsignedLeb128Size(pData->virtualMethods[i].accessFlags);
            len+=unsignedLeb128Size(pData->virtualMethods[i].codeOff);
        }
    }

    uint8_t * store = (uint8_t *) malloc(len);

    if (!store) {
        return NULL;
    }

    uint8_t * result=store;

    writeLeb128(&store,pData->header.staticFieldsSize);
    writeLeb128(&store,pData->header.instanceFieldsSize);
    writeLeb128(&store,pData->header.directMethodsSize);
    writeLeb128(&store,pData->header.virtualMethodsSize);

    if (pData->staticFields) {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++) {
            writeLeb128(&store,pData->staticFields[i].fieldIdx);
            writeLeb128(&store,pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields) {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++) {
            writeLeb128(&store,pData->instanceFields[i].fieldIdx);
            writeLeb128(&store,pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods) {
        for (uint32_t i=0; i<pData->header.directMethodsSize; i++) {
            writeLeb128(&store,pData->directMethods[i].methodIdx);
            writeLeb128(&store,pData->directMethods[i].accessFlags);
            writeLeb128(&store,pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods) {
        for (uint32_t i=0; i<pData->header.virtualMethodsSize; i++) {
            writeLeb128(&store,pData->virtualMethods[i].methodIdx);
            writeLeb128(&store,pData->virtualMethods[i].accessFlags);
            writeLeb128(&store,pData->virtualMethods[i].codeOff);
        }
    }

    free(pData);
    return result;
}

uint8_t* get_code_end(const u1** pData)
{
    uint32_t num_of_list = readUnsignedLeb128(pData);
    for (;num_of_list>0;num_of_list--) {
        int32_t num_of_handlers=readSignedLeb128(pData);
        int num=num_of_handlers;
        if (num_of_handlers<=0) {
            num=-num_of_handlers;
        }
        for (; num > 0; num--) {
            readUnsignedLeb128(pData);
            readUnsignedLeb128(pData);
        }
        if (num_of_handlers<=0) {
            readUnsignedLeb128(pData);
        }
    }
    return (uint8_t*)(*pData);
}

void log_and_clear_exception(char* dump_path) {
	char log_info[512]={0};
	Thread* self = dvmThreadSelf();
	if(dvmCheckException(self)) {
		Object* excep = dvmGetException(self);
		sprintf(log_info, "Exception type = %s\n", excep->clazz->descriptor);
		write_log(dump_path, log_info);
		dvmClearException(self);
	}
	return;
}

void get_pack_type(DvmDex* pDvmDex, char* pack_type) {
	char type_path[512]={0};
	char pack_name[256]={0};
	int fd_type;
	DexFile* pDexFile=pDvmDex->pDexFile;
	
	if(0 == get_pack_name(pack_name)) {
		sprintf(type_path, "/data/local/tmp/%s/pack_type.txt", pack_name);
	}
	
	if(!access(type_path, R_OK)) {
		fd_type = open(type_path, O_RDWR|O_CREAT|O_APPEND, S_IRWXU|S_IRWXG|S_IRWXO);
		if(fd_type) {
			read(fd_type, pack_type, 64);
			close(fd_type);
		}
		return;
	}
	
	for(u4 i=0; i<pDexFile->pHeader->classDefsSize; i++) {
		const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
		const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);
		
		if(!strcmp(descriptor, "Lcom/edog/AppWrapper;")) {
			strcpy(pack_type, "na_jia");
			break;
		}
		if(!strcmp(descriptor, "Lcom/payegis/ProxyApplication;")) {
			strcpy(pack_type, "tong_fu_dun");
			break;
		}
		if(!strcmp(descriptor, "Lcom/secneo/apkwrapper/ApplicationWrapper;")) {
			strcpy(pack_type, "bang_bang");
			break;
		}
		if(!strcmp(descriptor, "Lcom/shell/NativeApplication;")) {
			strcpy(pack_type, "ai_jia_mi");
			break;
		}
		if(!strcmp(descriptor, "Lcom/baidu/protect/StubApplication;")) {
			strcpy(pack_type, "bai_du");
			break;
		}
		
		if(!strcmp(descriptor, "Lcom/secneo/guard/ApplicationWrapper;")) {
			strcpy(pack_type, "bang_bang_free");
			break;
		}
		if(strstr(descriptor, "Lcom/qihoo/util;")) {
			strcpy(pack_type, "360_free");
			break;
		}
		if(strstr(descriptor, "Lcom/ali/fixHelper;")) {
			strcpy(pack_type, "ali_free");
			break;
		}
	}
	
	fd_type = open(type_path, O_RDWR|O_CREAT|O_APPEND, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd_type) {
		write(fd_type, pack_type, strlen(pack_type));
		close(fd_type);
	}
	
	return;
}

extern  ClassObject* loadClassFromDex(DvmDex* pDvmDex, const DexClassDef* pClassDef, Object* loader);
ClassObject* getClassObject(DvmDex* pDvmDex, const char* descriptor, Object* loader)
{
	ClassObject* clazz;
	const DexClassDef* pClassDef;
	clazz = dvmLookupClass(descriptor, loader, true);
	if(clazz == NULL) {
		pClassDef = dexFindClass(pDvmDex->pDexFile, descriptor);
		clazz = loadClassFromDex(pDvmDex, pClassDef, loader);
		dvmReleaseTrackedAlloc((Object*) clazz, NULL);
	}
	dvmLinkClass(clazz);
	return clazz;
}

void call_dvmInitClass_dump_whole(char* dump_path, Object* loader, DvmDex* pDvmDex) {
	char log_info[512]={0};
	char temp[512]={0};
	int fd;
	DexFile* pDexFile=pDvmDex->pDexFile;
	//MemMapping* mem=&pDvmDex->memMap;
	
	if(pDexFile->pHeader->classDefsSize < 60) {
		return;
	}
	
	//begin dump class
	u4 time=dvmGetRelativeTimeMsec();
	sprintf(log_info, "Dump class begin : %d ms\n", time);
	write_log(dump_path, log_info);
	
	//u4 offset_after_dex_class_defs = pDexFile->pHeader->classDefsOff+sizeof(DexClassDef)*pDexFile->pHeader->classDefsSize;
	for(u4 i=0; i<pDexFile->pHeader->classDefsSize; i++) {
		const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
		const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);
		
		sprintf(log_info, "Begin deal with class[%d] : %s\n", i, descriptor);
		write_log(dump_path, log_info);
		
		ClassObject* clazz = getClassObject(pDvmDex, descriptor, loader);
		log_and_clear_exception(dump_path);
		if(!clazz) {
			sprintf(log_info, "Call getClassObject fail, class = %s\n", descriptor);
			write_log(dump_path, log_info);
			continue;
		}
		sprintf(log_info, "Call getClassObject success, class = %s\n", descriptor);
		write_log(dump_path, log_info);
		
		if(!dvmIsClassInitialized(clazz)) {
			if(dvmInitClass(clazz)) {
				sprintf(log_info, "Call dvmInitClass success, class = %s\n", descriptor);
				write_log(dump_path, log_info);
			}
			else {
				sprintf(log_info, "Call dvmInitClass fail, class = %s\n", descriptor);
				write_log(dump_path, log_info);
				log_and_clear_exception(dump_path);
			}
		}
		else {
			sprintf(log_info, "Not call dvmInitClass, class : %s has already initialized\n", descriptor);
			write_log(dump_path, log_info);
		}
	}
	
	//dump DexFile_init.dex
	strcpy(temp, dump_path);
	strcat(temp, "unpack_DexFile.dex");
	fd = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd) {
		write(fd, pDexFile->baseAddr, pDexFile->pHeader->fileSize);
		close(fd);
	}
	sprintf(log_info, "Dump DexFile_init.dex, pDexFile->baseAddr = 0x%x, pDexFile->pHeader->fileSize = 0x%x\n", (int)pDexFile->baseAddr, (int)pDexFile->pHeader->fileSize);
	write_log(dump_path, log_info);
	
	time=dvmGetRelativeTimeMsec();
	sprintf(log_info, "Dump class end : %d ms\n", time);
	write_log(dump_path, log_info);
	
	return;
}

void call_dvmInitClass_dump_class(char* dump_path, Object* loader, DvmDex* pDvmDex) {
	char log_info[512]={0};
	char temp[512]={0};
	int fd;
	int fd_dex_class_defs;
	int fd_extra;
	char padding=0;
	DexFile* pDexFile=pDvmDex->pDexFile;
	//MemMapping* mem=&pDvmDex->memMap;
	
	//begin dump class
	u4 time=dvmGetRelativeTimeMsec();
	sprintf(log_info, "Dump class begin : %d ms\n", time);
	write_log(dump_path, log_info);
	
	//dump part_before_dex_class_defs
	strcpy(temp, dump_path);
	strcat(temp, "part_before_dex_class_defs");
	fd = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd) {
		write(fd, pDexFile->baseAddr, pDexFile->pHeader->classDefsOff);
		close(fd);
	}
	sprintf(log_info, "Dump part_before_dex_class_defs, pDexFile->baseAddr = 0x%x, pDexFile->pHeader->classDefsOff = 0x%x\n", (int)pDexFile->baseAddr, (int)pDexFile->pHeader->classDefsOff);
	write_log(dump_path, log_info);
	//dump part_after_dex_class_defs
	strcpy(temp, dump_path);
	strcat(temp, "part_after_dex_class_defs");
	int offset_after_dex_class_defs = pDexFile->pHeader->classDefsOff+sizeof(DexClassDef)*pDexFile->pHeader->classDefsSize;
	int len_after_dex_class_defs = pDexFile->pHeader->fileSize - offset_after_dex_class_defs;
	fd = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd) {
		write(fd, pDexFile->baseAddr+offset_after_dex_class_defs, len_after_dex_class_defs);
		close(fd);
	}
	sprintf(log_info, "Dump part_after_dex_class_defs, offset_after_dex_class_defs = 0x%x, len_after_dex_class_defs = 0x%x\n", (int)offset_after_dex_class_defs, (int)len_after_dex_class_defs);
	write_log(dump_path, log_info);
	
	strcpy(temp, dump_path);
	strcat(temp, "dex_class_defs");
	fd_dex_class_defs = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(!fd_dex_class_defs) {
		return;
	}
	
	strcpy(temp, dump_path);
	strcat(temp, "extra");
	fd_extra = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(!fd_extra) {
		return;
	}
	
	sprintf(log_info, "Begin loop deal with class\n\n\n");
	write_log(dump_path, log_info);
	
	u4 offset_dex_end = pDexFile->pHeader->fileSize;
	while(offset_dex_end&3) {
		write(fd_extra, &padding, 1);
		offset_dex_end++;
	}
	
	//u4 offset_after_dex_class_defs = pDexFile->pHeader->classDefsOff+sizeof(DexClassDef)*pDexFile->pHeader->classDefsSize;
	for(u4 i=0; i<pDexFile->pHeader->classDefsSize; i++) {
		const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
		const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);
		
		sprintf(log_info, "Begin deal with class[%d] : %s\n", i, descriptor);
		write_log(dump_path, log_info);
		
		ClassObject* clazz = getClassObject(pDvmDex, descriptor, loader);
		log_and_clear_exception(dump_path);
		if(!clazz) {
			sprintf(log_info, "Call getClassObject fail, class = %s\n", descriptor);
			write_log(dump_path, log_info);
			write(fd_dex_class_defs, pClassDef, sizeof(DexClassDef));
			continue;
		}
		sprintf(log_info, "Call getClassObject success, class = %s\n", descriptor);
		write_log(dump_path, log_info);
		
		if(!dvmIsClassInitialized(clazz)) {
			if(dvmInitClass(clazz)) {
				sprintf(log_info, "Call dvmInitClass success, class = %s\n", descriptor);
				write_log(dump_path, log_info);
			}
			else {
				sprintf(log_info, "Call dvmInitClass fail, class = %s\n", descriptor);
				write_log(dump_path, log_info);
				log_and_clear_exception(dump_path);
			}
		}
		else {
			sprintf(log_info, "Not call dvmInitClass, class : %s has already initialized\n", descriptor);
			write_log(dump_path, log_info);
		}
		
		const u1* class_data = dexGetClassData(pDexFile, pClassDef);
		DexClassData* pClassData = ReadClassData(&class_data);
		if(!pClassData) {
			sprintf(log_info, "Call ReadClassData fail, class = %s\n", descriptor);
			write_log(dump_path, log_info);
			write(fd_dex_class_defs, pClassDef, sizeof(DexClassDef));
			log_and_clear_exception(dump_path);
			continue;
		}
		sprintf(log_info, "Call ReadClassData success, class = %s\n", descriptor);
		write_log(dump_path, log_info);
		
		if(pClassData->directMethods) {
			for(u4 i=0; i<pClassData->header.directMethodsSize; i++) {
				Method* method = &(clazz->directMethods[i]);
				
				sprintf(log_info, "directMethods[%d], method->accessFlags = 0x%x, method->insns = 0x%x\n", i, method->accessFlags, (int)method->insns);
				write_log(dump_path, log_info);
				
				u4 accessFlags = method->accessFlags & ACC_METHOD_MASK;
				pClassData->directMethods[i].accessFlags = accessFlags;
				
				if(!method->insns || accessFlags&ACC_NATIVE) {
					pClassData->directMethods[i].codeOff = 0;
					continue;
				}
				
				pClassData->directMethods[i].codeOff = offset_dex_end;
				DexCode* pCode = (DexCode*)((u4)method->insns-16);
				uint8_t* code_begin = (uint8_t*)pCode;
				int code_len = 0;
				if(pCode->triesSize) {
					const u1* handler_data = dexGetCatchHandlerData(pCode);
					const u1** phandler = (const u1**)&handler_data;
					uint8_t* code_end = get_code_end(phandler);
					code_len = (int)(code_end-code_begin);
				}
				else {
					code_len = 16 + pCode->insnsSize*2;
				}
				
				sprintf(log_info, "code_begin = 0x%x, code_len = 0x%x\n", (int)code_begin, code_len);
				write_log(dump_path, log_info);
				
				write(fd_extra, code_begin, code_len);
				offset_dex_end += code_len;
				while(offset_dex_end&3) {
					write(fd_extra, &padding, 1);
					offset_dex_end++;
				}
			}
		}
		
		if(pClassData->virtualMethods) {
			for(u4 i=0; i<pClassData->header.virtualMethodsSize; i++) {
				Method* method = &(clazz->virtualMethods[i]);
				
				sprintf(log_info, "virtualMethods[%d], method->accessFlags = 0x%x, method->insns = 0x%x\n", i, method->accessFlags, (int)method->insns);
				write_log(dump_path, log_info);
				
				u4 accessFlags = method->accessFlags & ACC_METHOD_MASK;
				pClassData->virtualMethods[i].accessFlags = accessFlags;
				
				if(!method->insns || accessFlags&ACC_NATIVE) {
					pClassData->virtualMethods[i].codeOff = 0;
					continue;
				}
				
				pClassData->virtualMethods[i].codeOff = offset_dex_end;
				DexCode* pCode = (DexCode*)((u4)method->insns-16);
				uint8_t* code_begin = (uint8_t*)pCode;
				int code_len = 0;
				if(pCode->triesSize) {
					const u1* handler_data = dexGetCatchHandlerData(pCode);
					const u1** phandler = (const u1**)&handler_data;
					uint8_t* code_end = get_code_end(phandler);
					code_len = (int)(code_end-code_begin);
				}
				else {
					code_len = 16 + pCode->insnsSize*2;
				}
				
				sprintf(log_info, "code_begin = 0x%x, code_len = 0x%x\n", (int)code_begin, code_len);
				write_log(dump_path, log_info);
				
				write(fd_extra, code_begin, code_len);
				offset_dex_end += code_len;
				while(offset_dex_end&3) {
					write(fd_extra, &padding, 1);
					offset_dex_end++;
				}
			}
		}
		
		DexClassDef class_def_copy = *pClassDef;
		class_def_copy.classDataOff = offset_dex_end;
		
		int encoded_class_data_len = 0;
		uint8_t* encoded_class_data = EncodeClassData(pClassData, encoded_class_data_len);
		write(fd_extra, encoded_class_data, encoded_class_data_len);
		offset_dex_end += encoded_class_data_len;
		while(offset_dex_end&3) {
			write(fd_extra, &padding, 1);
			offset_dex_end++;
		}
		free(encoded_class_data);
		
		write(fd_dex_class_defs, &class_def_copy, sizeof(DexClassDef));
		
		sprintf(log_info, "End deal with class %s\n\n", descriptor);
		write_log(dump_path, log_info);
	}
	
	close(fd_dex_class_defs);
	close(fd_extra);
	//concat all the files
	struct stat st;
	char* addr;
	strcpy(temp, dump_path);
	strcat(temp, "unpack_call_dvmInitClass_dump_class.dex");
	int fd_unpack = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	
	strcpy(temp, dump_path);
	strcat(temp, "part_before_dex_class_defs");
	fd = open(temp, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	fstat(fd, &st);
	addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	write(fd_unpack, addr, st.st_size);
	munmap(addr, st.st_size);
	close(fd);
	
	strcpy(temp, dump_path);
	strcat(temp, "dex_class_defs");
	fd = open(temp, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	fstat(fd, &st);
	addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	write(fd_unpack, addr, st.st_size);
	munmap(addr, st.st_size);
	close(fd);
	
	strcpy(temp, dump_path);
	strcat(temp, "part_after_dex_class_defs");
	fd = open(temp, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	fstat(fd, &st);
	addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	write(fd_unpack, addr, st.st_size);
	munmap(addr, st.st_size);
	close(fd);
	
	strcpy(temp, dump_path);
	strcat(temp, "extra");
	fd = open(temp, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	fstat(fd, &st);
	addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	write(fd_unpack, addr, st.st_size);
	munmap(addr, st.st_size);
	close(fd);
	
	close(fd_unpack);
	
	time=dvmGetRelativeTimeMsec();
	sprintf(log_info, "Dump class end : %d ms\n", time);
	write_log(dump_path, log_info);
	
	return;
}

void dump_class(char* dump_path, Object* loader, DvmDex* pDvmDex) {
	char log_info[512]={0};
	char temp[512]={0};
	int fd;
	int fd_dex_class_defs;
	int fd_extra;
	char padding=0;
	DexFile* pDexFile=pDvmDex->pDexFile;
	//MemMapping* mem=&pDvmDex->memMap;
	
	//begin dump class
	u4 time=dvmGetRelativeTimeMsec();
	sprintf(log_info, "Dump class begin : %d ms\n", time);
	write_log(dump_path, log_info);
	
	//dump part_before_dex_class_defs
	strcpy(temp, dump_path);
	strcat(temp, "part_before_dex_class_defs");
	fd = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd) {
		write(fd, pDexFile->baseAddr, pDexFile->pHeader->classDefsOff);
		close(fd);
	}
	sprintf(log_info, "Dump part_before_dex_class_defs, pDexFile->baseAddr = 0x%x, pDexFile->pHeader->classDefsOff = 0x%x\n", (int)pDexFile->baseAddr, (int)pDexFile->pHeader->classDefsOff);
	write_log(dump_path, log_info);
	//dump part_after_dex_class_defs
	strcpy(temp, dump_path);
	strcat(temp, "part_after_dex_class_defs");
	int offset_after_dex_class_defs = pDexFile->pHeader->classDefsOff+sizeof(DexClassDef)*pDexFile->pHeader->classDefsSize;
	int len_after_dex_class_defs = pDexFile->pHeader->fileSize - offset_after_dex_class_defs;
	fd = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd) {
		write(fd, pDexFile->baseAddr+offset_after_dex_class_defs, len_after_dex_class_defs);
		close(fd);
	}
	sprintf(log_info, "Dump part_after_dex_class_defs, offset_after_dex_class_defs = 0x%x, len_after_dex_class_defs = 0x%x\n", (int)offset_after_dex_class_defs, (int)len_after_dex_class_defs);
	write_log(dump_path, log_info);
	
	strcpy(temp, dump_path);
	strcat(temp, "dex_class_defs");
	fd_dex_class_defs = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(!fd_dex_class_defs) {
		return;
	}
	
	strcpy(temp, dump_path);
	strcat(temp, "extra");
	fd_extra = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(!fd_extra) {
		return;
	}
	
	sprintf(log_info, "Begin loop deal with class\n\n\n");
	write_log(dump_path, log_info);
	
	u4 offset_dex_end = pDexFile->pHeader->fileSize;
	while(offset_dex_end&3) {
		write(fd_extra, &padding, 1);
		offset_dex_end++;
	}
	
	//u4 offset_after_dex_class_defs = pDexFile->pHeader->classDefsOff+sizeof(DexClassDef)*pDexFile->pHeader->classDefsSize;
	for(u4 i=0; i<pDexFile->pHeader->classDefsSize; i++) {
		const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
		const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);
		
		sprintf(log_info, "Begin deal with class[%d] : %s\n", i, descriptor);
		write_log(dump_path, log_info);
		
		ClassObject* clazz = getClassObject(pDvmDex, descriptor, loader);
		log_and_clear_exception(dump_path);
		if(!clazz) {
			sprintf(log_info, "Call getClassObject fail, class = %s\n", descriptor);
			write_log(dump_path, log_info);
			write(fd_dex_class_defs, pClassDef, sizeof(DexClassDef));
			continue;
		}
		sprintf(log_info, "Call getClassObject success, class = %s\n", descriptor);
		write_log(dump_path, log_info);
		/*
		if(!dvmIsClassInitialized(clazz)) {
			if(dvmInitClass(clazz)) {
				sprintf(log_info, "Call dvmInitClass success, class = %s\n", descriptor);
				write_log(dump_path, log_info);
			}
			else {
				sprintf(log_info, "Call dvmInitClass fail, class = %s\n", descriptor);
				write_log(dump_path, log_info);
				log_and_clear_exception(dump_path);
			}
		}
		else {
			sprintf(log_info, "Not call dvmInitClass, class : %s has already initialized\n", descriptor);
			write_log(dump_path, log_info);
		}
		*/
		const u1* class_data = dexGetClassData(pDexFile, pClassDef);
		DexClassData* pClassData = ReadClassData(&class_data);
		if(!pClassData) {
			sprintf(log_info, "Call ReadClassData fail, class = %s\n", descriptor);
			write_log(dump_path, log_info);
			write(fd_dex_class_defs, pClassDef, sizeof(DexClassDef));
			log_and_clear_exception(dump_path);
			continue;
		}
		sprintf(log_info, "Call ReadClassData success, class = %s\n", descriptor);
		write_log(dump_path, log_info);
		
		if(pClassData->directMethods) {
			for(u4 i=0; i<pClassData->header.directMethodsSize; i++) {
				Method* method = &(clazz->directMethods[i]);
				
				sprintf(log_info, "directMethods[%d], method->accessFlags = 0x%x, method->insns = 0x%x\n", i, method->accessFlags, (int)method->insns);
				write_log(dump_path, log_info);
				
				u4 accessFlags = method->accessFlags & ACC_METHOD_MASK;
				pClassData->directMethods[i].accessFlags = accessFlags;
				
				if(!method->insns || accessFlags&ACC_NATIVE) {
					pClassData->directMethods[i].codeOff = 0;
					continue;
				}
				
				pClassData->directMethods[i].codeOff = offset_dex_end;
				DexCode* pCode = (DexCode*)((u4)method->insns-16);
				uint8_t* code_begin = (uint8_t*)pCode;
				int code_len = 0;
				if(pCode->triesSize) {
					const u1* handler_data = dexGetCatchHandlerData(pCode);
					const u1** phandler = (const u1**)&handler_data;
					uint8_t* code_end = get_code_end(phandler);
					code_len = (int)(code_end-code_begin);
				}
				else {
					code_len = 16 + pCode->insnsSize*2;
				}
				
				sprintf(log_info, "code_begin = 0x%x, code_len = 0x%x\n", (int)code_begin, code_len);
				write_log(dump_path, log_info);
				
				write(fd_extra, code_begin, code_len);
				offset_dex_end += code_len;
				while(offset_dex_end&3) {
					write(fd_extra, &padding, 1);
					offset_dex_end++;
				}
			}
		}
		
		if(pClassData->virtualMethods) {
			for(u4 i=0; i<pClassData->header.virtualMethodsSize; i++) {
				Method* method = &(clazz->virtualMethods[i]);
				
				sprintf(log_info, "virtualMethods[%d], method->accessFlags = 0x%x, method->insns = 0x%x\n", i, method->accessFlags, (int)method->insns);
				write_log(dump_path, log_info);
				
				u4 accessFlags = method->accessFlags & ACC_METHOD_MASK;
				pClassData->virtualMethods[i].accessFlags = accessFlags;
				
				if(!method->insns || accessFlags&ACC_NATIVE) {
					pClassData->virtualMethods[i].codeOff = 0;
					continue;
				}
				
				pClassData->virtualMethods[i].codeOff = offset_dex_end;
				DexCode* pCode = (DexCode*)((u4)method->insns-16);
				uint8_t* code_begin = (uint8_t*)pCode;
				int code_len = 0;
				if(pCode->triesSize) {
					const u1* handler_data = dexGetCatchHandlerData(pCode);
					const u1** phandler = (const u1**)&handler_data;
					uint8_t* code_end = get_code_end(phandler);
					code_len = (int)(code_end-code_begin);
				}
				else {
					code_len = 16 + pCode->insnsSize*2;
				}
				
				sprintf(log_info, "code_begin = 0x%x, code_len = 0x%x\n", (int)code_begin, code_len);
				write_log(dump_path, log_info);
				
				write(fd_extra, code_begin, code_len);
				offset_dex_end += code_len;
				while(offset_dex_end&3) {
					write(fd_extra, &padding, 1);
					offset_dex_end++;
				}
			}
		}
		
		DexClassDef class_def_copy = *pClassDef;
		class_def_copy.classDataOff = offset_dex_end;
		
		int encoded_class_data_len = 0;
		uint8_t* encoded_class_data = EncodeClassData(pClassData, encoded_class_data_len);
		write(fd_extra, encoded_class_data, encoded_class_data_len);
		offset_dex_end += encoded_class_data_len;
		while(offset_dex_end&3) {
			write(fd_extra, &padding, 1);
			offset_dex_end++;
		}
		free(encoded_class_data);
		
		write(fd_dex_class_defs, &class_def_copy, sizeof(DexClassDef));
		
		sprintf(log_info, "End deal with class %s\n\n", descriptor);
		write_log(dump_path, log_info);
	}
	
	close(fd_dex_class_defs);
	close(fd_extra);
	//concat all the files
	struct stat st;
	char* addr;
	strcpy(temp, dump_path);
	strcat(temp, "unpack_dump_class.dex");
	int fd_unpack = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	
	strcpy(temp, dump_path);
	strcat(temp, "part_before_dex_class_defs");
	fd = open(temp, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	fstat(fd, &st);
	addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	write(fd_unpack, addr, st.st_size);
	munmap(addr, st.st_size);
	close(fd);
	
	strcpy(temp, dump_path);
	strcat(temp, "dex_class_defs");
	fd = open(temp, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	fstat(fd, &st);
	addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	write(fd_unpack, addr, st.st_size);
	munmap(addr, st.st_size);
	close(fd);
	
	strcpy(temp, dump_path);
	strcat(temp, "part_after_dex_class_defs");
	fd = open(temp, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	fstat(fd, &st);
	addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	write(fd_unpack, addr, st.st_size);
	munmap(addr, st.st_size);
	close(fd);
	
	strcpy(temp, dump_path);
	strcat(temp, "extra");
	fd = open(temp, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	fstat(fd, &st);
	addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	write(fd_unpack, addr, st.st_size);
	munmap(addr, st.st_size);
	close(fd);
	
	close(fd_unpack);
	
	time=dvmGetRelativeTimeMsec();
	sprintf(log_info, "Dump class end : %d ms\n", time);
	write_log(dump_path, log_info);
	
	return;
}

void dumpDex(DvmDex* pDvmDex, Object* loader, int cookie) {
	char dump_path[512]={0};
	char log_info[512]={0};
	char temp[512]={0};
	char pack_type[64]={0};
	int fd;
	//If the process is system, then return
	if(getuid() == 0) {
		return;
	}
	
	mode_t old_mode = umask(0);  //set the all mask
	if(-1 == get_dump_path(dump_path, cookie)) {
		return;
	}
	sprintf(log_info, "dump_path = %s\n", dump_path);
	write_log(dump_path, log_info);
	
	DexFile *pDexFile=pDvmDex->pDexFile;
	MemMapping *mem=&pDvmDex->memMap;
	//fix DexFile struct
	if(strncmp((char*)mem->addr, "dey\n", 4)) {
		pDexFile->baseAddr = (const u1*)mem->addr;
	}
	else {
		pDexFile->baseAddr = (const u1*)mem->addr + 0x28;
	}
	pDexFile->pHeader = (DexHeader*)pDexFile->baseAddr;
	//dump DvmDex.dex
	strcpy(temp, dump_path);
	strcat(temp, "DvmDex.dex");
	fd = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd) {
		write(fd, mem->addr, mem->length);
		close(fd);
	}
	sprintf(log_info, "Dump DvmDex.dex, mem->addr = 0x%x, mem->length = 0x%x\n", (int)mem->addr, (int)mem->length);
	write_log(dump_path, log_info);
	//dump DexFile.dex
	strcpy(temp, dump_path);
	strcat(temp, "DexFile.dex");
	fd = open(temp, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd) {
		write(fd, pDexFile->baseAddr, pDexFile->pHeader->fileSize);
		close(fd);
	}
	sprintf(log_info, "Dump DexFile.dex, pDexFile->baseAddr = 0x%x, pDexFile->pHeader->fileSize = 0x%x\n", (int)pDexFile->baseAddr, (int)pDexFile->pHeader->fileSize);
	write_log(dump_path, log_info);
	
	get_pack_type(pDvmDex, pack_type);
/*	
	if(!strcmp(pack_type, "na_jia")) {
		call_dvmInitClass_dump_whole(dump_path, loader, pDvmDex);
	}
	else if(!strcmp(pack_type, "tong_fu_dun")) {
		call_dvmInitClass_dump_class(dump_path, loader, pDvmDex);
	}
	else if(!strcmp(pack_type, "ai_jia_mi") || !strcmp(pack_type, "bai_du") || !strcmp(pack_type, "bang_bang") || !strcmp(pack_type, "ali_free")) {
		dump_class(dump_path, loader, pDvmDex);
	}
*/	
	umask(old_mode);
}

//------------------------added end----------------------//

/*
 * private static Class defineClassNative(String name, ClassLoader loader,
 *      int cookie)
 *
 * Load a class from a DEX file.  This is roughly equivalent to defineClass()
 * in a regular VM -- it's invoked by the class loader to cause the
 * creation of a specific class.  The difference is that the search for and
 * reading of the bytes is done within the VM.
 *
 * The class name is a "binary name", e.g. "java.lang.String".
 *
 * Returns a null pointer with no exception if the class was not found.
 * Throws an exception on other failures.
 */
static void Dalvik_dalvik_system_DexFile_defineClassNative(const u4* args,
    JValue* pResult)
{
    StringObject* nameObj = (StringObject*) args[0];
    Object* loader = (Object*) args[1];
    int cookie = args[2];
    ClassObject* clazz = NULL;
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;
    DvmDex* pDvmDex;
    char* name;
    char* descriptor;

    name = dvmCreateCstrFromString(nameObj);
    descriptor = dvmDotToDescriptor(name);
    ALOGV("--- Explicit class load '%s' l=%p c=0x%08x",
        descriptor, loader, cookie);
    free(name);

    if (!validateCookie(cookie))
        RETURN_VOID();

    if (pDexOrJar->isDex)
        pDvmDex = dvmGetRawDexFileDex(pDexOrJar->pRawDexFile);
    else
        pDvmDex = dvmGetJarFileDex(pDexOrJar->pJarFile);

    /* once we load something, we can't unmap the storage */
    pDexOrJar->okayToFree = false;
	
	dumpDex(pDvmDex, loader, cookie);  //young.wang add dump the dex file
	
    clazz = dvmDefineClass(pDvmDex, descriptor, loader);
    Thread* self = dvmThreadSelf();
    if (dvmCheckException(self)) {
        /*
         * If we threw a "class not found" exception, stifle it, since the
         * contract in the higher method says we simply return null if
         * the class is not found.
         */
        Object* excep = dvmGetException(self);
        if (strcmp(excep->clazz->descriptor,
                   "Ljava/lang/ClassNotFoundException;") == 0 ||
            strcmp(excep->clazz->descriptor,
                   "Ljava/lang/NoClassDefFoundError;") == 0)
        {
            dvmClearException(self);
        }
        clazz = NULL;
    }

    free(descriptor);
    RETURN_PTR(clazz);
}

/*
 * private static String[] getClassNameList(int cookie)
 *
 * Returns a String array that holds the names of all classes in the
 * specified DEX file.
 */
static void Dalvik_dalvik_system_DexFile_getClassNameList(const u4* args,
    JValue* pResult)
{
    int cookie = args[0];
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;
    Thread* self = dvmThreadSelf();

    if (!validateCookie(cookie))
        RETURN_VOID();

    DvmDex* pDvmDex;
    if (pDexOrJar->isDex)
        pDvmDex = dvmGetRawDexFileDex(pDexOrJar->pRawDexFile);
    else
        pDvmDex = dvmGetJarFileDex(pDexOrJar->pJarFile);
    assert(pDvmDex != NULL);
    DexFile* pDexFile = pDvmDex->pDexFile;

    int count = pDexFile->pHeader->classDefsSize;
    ClassObject* arrayClass =
        dvmFindArrayClassForElement(gDvm.classJavaLangString);
    ArrayObject* stringArray =
        dvmAllocArrayByClass(arrayClass, count, ALLOC_DEFAULT);
    if (stringArray == NULL) {
        /* probably OOM */
        ALOGD("Failed allocating array of %d strings", count);
        assert(dvmCheckException(self));
        RETURN_VOID();
    }

    int i;
    for (i = 0; i < count; i++) {
        const DexClassDef* pClassDef = dexGetClassDef(pDexFile, i);
        const char* descriptor =
            dexStringByTypeIdx(pDexFile, pClassDef->classIdx);

        char* className = dvmDescriptorToDot(descriptor);
        StringObject* str = dvmCreateStringFromCstr(className);
        dvmSetObjectArrayElement(stringArray, i, (Object *)str);
        dvmReleaseTrackedAlloc((Object *)str, self);
        free(className);
    }

    dvmReleaseTrackedAlloc((Object*)stringArray, self);
    RETURN_PTR(stringArray);
}

/*
 * public static boolean isDexOptNeeded(String fileName)
 *         throws FileNotFoundException, IOException
 *
 * Returns true if the VM believes that the apk/jar file is out of date
 * and should be passed through "dexopt" again.
 *
 * @param fileName the absolute path to the apk/jar file to examine.
 * @return true if dexopt should be called on the file, false otherwise.
 * @throws java.io.FileNotFoundException if fileName is not readable,
 *         not a file, or not present.
 * @throws java.io.IOException if fileName is not a valid apk/jar file or
 *         if problems occur while parsing it.
 * @throws java.lang.NullPointerException if fileName is null.
 * @throws dalvik.system.StaleDexCacheError if the optimized dex file
 *         is stale but exists on a read-only partition.
 */
static void Dalvik_dalvik_system_DexFile_isDexOptNeeded(const u4* args,
    JValue* pResult)
{
    StringObject* nameObj = (StringObject*) args[0];
    char* name;
    DexCacheStatus status;
    int result;

    name = dvmCreateCstrFromString(nameObj);
    if (name == NULL) {
        dvmThrowNullPointerException("fileName == null");
        RETURN_VOID();
    }
    if (access(name, R_OK) != 0) {
        dvmThrowFileNotFoundException(name);
        free(name);
        RETURN_VOID();
    }
    status = dvmDexCacheStatus(name);
    ALOGV("dvmDexCacheStatus(%s) returned %d", name, status);

    result = true;
    switch (status) {
    default: //FALLTHROUGH
    case DEX_CACHE_BAD_ARCHIVE:
        dvmThrowIOException(name);
        result = -1;
        break;
    case DEX_CACHE_OK:
        result = false;
        break;
    case DEX_CACHE_STALE:
        result = true;
        break;
    case DEX_CACHE_STALE_ODEX:
        dvmThrowStaleDexCacheError(name);
        result = -1;
        break;
    }
    free(name);

    if (result >= 0) {
        RETURN_BOOLEAN(result);
    } else {
        RETURN_VOID();
    }
}

const DalvikNativeMethod dvm_dalvik_system_DexFile[] = {
    { "openDexFileNative",  "(Ljava/lang/String;Ljava/lang/String;I)I",
        Dalvik_dalvik_system_DexFile_openDexFileNative },
    { "openDexFile",        "([B)I",
        Dalvik_dalvik_system_DexFile_openDexFile_bytearray },
    { "closeDexFile",       "(I)V",
        Dalvik_dalvik_system_DexFile_closeDexFile },
    { "defineClassNative",  "(Ljava/lang/String;Ljava/lang/ClassLoader;I)Ljava/lang/Class;",
        Dalvik_dalvik_system_DexFile_defineClassNative },
    { "getClassNameList",   "(I)[Ljava/lang/String;",
        Dalvik_dalvik_system_DexFile_getClassNameList },
    { "isDexOptNeeded",     "(Ljava/lang/String;)Z",
        Dalvik_dalvik_system_DexFile_isDexOptNeeded },
    { NULL, NULL, NULL },
};
