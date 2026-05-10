    #include "BoxCore.h"
#include "Log.h"
#include "IO.h"
#include <jni.h>
#include <JniHook/JniHook.h>
#include <Hook/VMClassLoaderHook.h>
#include <Hook/UnixFileSystemHook.h>
#include <Hook/FileSystemHook.h>
#include <Hook/BinderHook.h>
#include <Hook/DexFileHook.h>
#include <Hook/RuntimeHook.h>
#include "Utils/HexDump.h"
#include "hidden_api.h"

// ========== ADDED for mprotect & ANOGS hooks ==========
#include <sys/mman.h>
#include <dobby.h>
#include <dlfcn.h>
#include <string.h>
#include <android/log.h>
// =====================================================

struct {
    JavaVM *vm;
    jclass NativeCoreClass;
    jmethodID getCallingUidId;
    jmethodID redirectPathString;
    jmethodID redirectPathFile;
    jmethodID loadEmptyDex;
    jmethodID loadEmptyDexL;
    int api_level;
} VMEnv;


JNIEnv *getEnv() {
    JNIEnv *env;
    VMEnv.vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    return env;
}

JNIEnv *ensureEnvCreated() {
    JNIEnv *env = getEnv();
    if (env == NULL) {
        VMEnv.vm->AttachCurrentThread(&env, NULL);
    }
    return env;
}

int BoxCore::getCallingUid(JNIEnv *env, int orig) {
    env = ensureEnvCreated();
    return env->CallStaticIntMethod(VMEnv.NativeCoreClass, VMEnv.getCallingUidId, orig);
}

jstring BoxCore::redirectPathString(JNIEnv *env, jstring path) {
    env = ensureEnvCreated();
    return (jstring) env->CallStaticObjectMethod(VMEnv.NativeCoreClass, VMEnv.redirectPathString, path);
}

jobject BoxCore::redirectPathFile(JNIEnv *env, jobject path) {
    env = ensureEnvCreated();
    return env->CallStaticObjectMethod(VMEnv.NativeCoreClass, VMEnv.redirectPathFile, path);
}

jlongArray BoxCore::loadEmptyDex(JNIEnv *env) {
    env = ensureEnvCreated();
    return (jlongArray) env->CallStaticObjectMethod(VMEnv.NativeCoreClass, VMEnv.loadEmptyDex);
}

int BoxCore::getApiLevel() {
    return VMEnv.api_level;
}

JavaVM *BoxCore::getJavaVM() {
    return VMEnv.vm;
}

void nativeHook(JNIEnv *env) {
    BaseHook::init(env);
    UnixFileSystemHook::init(env);
    FileSystemHook::init();
    VMClassLoaderHook::init(env);

    BinderHook::init(env);
    DexFileHook::init(env);
}

void hideXposed(JNIEnv *env, jclass clazz) {
    ALOGD("set hideXposed");
    VMClassLoaderHook::hideXposed();
}

void init(JNIEnv *env, jobject clazz, jint api_level) {
    ALOGD("NativeCore init.");
    VMEnv.api_level = api_level;
    VMEnv.NativeCoreClass = (jclass) env->NewGlobalRef(env->FindClass(VMCORE_CLASS));
    VMEnv.getCallingUidId = env->GetStaticMethodID(VMEnv.NativeCoreClass, "getCallingUid", "(I)I");
    VMEnv.redirectPathString = env->GetStaticMethodID(VMEnv.NativeCoreClass, "redirectPath",
                                                      "(Ljava/lang/String;)Ljava/lang/String;");
    VMEnv.redirectPathFile = env->GetStaticMethodID(VMEnv.NativeCoreClass, "redirectPath",
                                                    "(Ljava/io/File;)Ljava/io/File;");
    VMEnv.loadEmptyDex = env->GetStaticMethodID(VMEnv.NativeCoreClass, "loadEmptyDex",
                                                "()[J");

    JniHook::InitJniHook(env, api_level);
}

void addIORule(JNIEnv *env, jclass clazz, jstring target_path,
               jstring relocate_path) {
    ALOGD("set addIORule");
    IO::addRule(env->GetStringUTFChars(target_path, JNI_FALSE),
                env->GetStringUTFChars(relocate_path, JNI_FALSE));
}

void enableIO(JNIEnv *env, jclass clazz) {
    ALOGD("set enableIO");
    IO::init(env);
    nativeHook(env);
}

bool disableHiddenApi(JNIEnv *env, jclass clazz) {
    ALOGD("set disableHiddenApi");
    if(!disable_hidden_api(env)){
        ALOGD("set disableHiddenApi Fail!!!");
        return false;
    }
    return true;
}

bool disableResourceLoading(JNIEnv *env, jclass clazz) {
    ALOGD("set disableResourceLoading");
    if(!disable_resource_loading()){
        ALOGD("set disableResourceLoading Fail!!!");
        return false;
    }
    return true;
}

// ========== ADDED: mprotect hook ==========
static int (*original_mprotect)(void *addr, size_t len, int prot);

int mprotect_hook(void *addr, size_t len, int prot) {
    __android_log_print(ANDROID_LOG_DEBUG, "BlackBox", "mprotect(%p, %zu, %d)", addr, len, prot);
    return original_mprotect(addr, len, prot);
}

void install_mprotect_hook() {
    void *mprotect_ptr = dlsym(RTLD_DEFAULT, "mprotect");
    if (mprotect_ptr) {
        DobbyHook(mprotect_ptr, (void*)mprotect_hook, (void**)&original_mprotect);
        __android_log_print(ANDROID_LOG_INFO, "BlackBox", "mprotect hook installed");
    } else {
        __android_log_print(ANDROID_LOG_ERROR, "BlackBox", "mprotect not found");
    }
}

// ========== ADDED: ANOGS Ioctl hook ==========
typedef void* (*AnoSDK_Ioctl_t)(int cmd, const char* input);
static AnoSDK_Ioctl_t original_anogs_ioctl = nullptr;

void* anogs_ioctl_hook(int cmd, const char* input) {
    __android_log_print(ANDROID_LOG_DEBUG, "ANOGS", "Ioctl called: cmd=%d, input=%s", cmd, input ? input : "null");
    // Patch the emulator / detection queries
    if (cmd == 10 || (input && strstr(input, "emulator"))) {
        // Return empty string to bypass check
        return (void*)"";
    }
    // For other commands, forward to original
    if (original_anogs_ioctl) {
        return original_anogs_ioctl(cmd, input);
    }
    return nullptr;
}

void install_anogs_hooks() {
    void *func = dlsym(RTLD_DEFAULT, "GCloud_AnoSDK_AnoSDK__Ioctl");
    if (!func) {
        // Try alternative symbol name
        func = dlsym(RTLD_DEFAULT, "_ZN7AnoSDK5IoctlEiPKc");
    }
    if (func) {
        DobbyHook(func, (void*)anogs_ioctl_hook, (void**)&original_anogs_ioctl);
        __android_log_print(ANDROID_LOG_INFO, "ANOGS", "Hook installed");
    } else {
        __android_log_print(ANDROID_LOG_WARN, "ANOGS", "ANOGS Ioctl symbol not found, skipping");
    }
}
// ==========================================

static JNINativeMethod gMethods[] = {
        {"disableHiddenApi", "()Z",                               (void *) disableHiddenApi},
        {"disableResourceLoading", "()Z",                         (void *) disableResourceLoading},
        {"hideXposed", "()V",                                     (void *) hideXposed},
        {"addIORule",  "(Ljava/lang/String;Ljava/lang/String;)V", (void *) addIORule},
        {"enableIO",   "()V",                                     (void *) enableIO},
        {"init",       "(I)V",                                    (void *) init},
};

int registerNativeMethods(JNIEnv *env, const char *className,
                          JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == nullptr) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

int registerNatives(JNIEnv *env) {
    if (!registerNativeMethods(env, VMCORE_CLASS, gMethods,
                               sizeof(gMethods) / sizeof(gMethods[0])))
        return JNI_FALSE;
    return JNI_TRUE;
}

void registerMethod(JNIEnv *jenv) {
    registerNatives(jenv);
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    VMEnv.vm = vm;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_EVERSION;
    }
    registerMethod(env);
    
    // ========== ADDED: Install hooks ==========
    install_mprotect_hook();
    install_anogs_hooks();
    // ==========================================
    
    return JNI_VERSION_1_6;
}
