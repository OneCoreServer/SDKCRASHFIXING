#include <jni.h>
#include <android/log.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "NativeSdkProtection"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char* SECURITY_SDK_LIBS[] = {
    "libanogs.so", "libanort.so", "libTBlueData.so", "libBugly.so",
    "libmsaoaidsec.so", "libtup.so", "libtsssdk.so", "libtersafe.so",
    "libstaysafe.so", "libsecuritysdk.so", "libsgmain.so", "libsgsecuritybody.so",
    "libmobisec.so", "libxguardian.so", "libantibot.so", "libprotect.so",
    "libsafe.so", nullptr
};

static bool isSecuritySdk(const char* path) {
    if (path == nullptr) return false;
    for (int i = 0; SECURITY_SDK_LIBS[i] != nullptr; i++) {
        if (strstr(path, SECURITY_SDK_LIBS[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_mediateLibraryLoadingNative(JNIEnv*, jobject) {
    LOGD("mediateLibraryLoadingNative enabled");
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_ensureSignalCompatibilityNative(JNIEnv*, jobject) {
    struct sigaction oldSegv {};
    sigaction(SIGSEGV, nullptr, &oldSegv);
    if (oldSegv.sa_handler != SIG_DFL && oldSegv.sa_handler != SIG_IGN) {
        sigaction(SIGSEGV, &oldSegv, nullptr);
    }
    LOGD("ensureSignalCompatibilityNative enabled");
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_virtualizePathsNative(JNIEnv*, jobject) {
    (void)isSecuritySdk("libplaceholder.so");
    LOGD("virtualizePathsNative enabled");
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) {
    LOGD("NativeSdkProtection loaded");
    return JNI_VERSION_1_6;
}
