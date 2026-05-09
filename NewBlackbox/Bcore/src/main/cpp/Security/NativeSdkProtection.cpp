#include <jni.h>
#include <signal.h>
#include <android/log.h>
#include <unistd.h>
#include <string.h>

#define LOG_TAG "NativeSdkProtection"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static const char* CONTAINER_PATHS[] = {
    "/blackbox/",
    "/BlackBox/",
    "/virtual/",
    "/parallel/",
    "/dual/",
    "/clone/",
    "/sandbox/",
    "/niunaijun/",
    "/bcore/",
    "/vbox/",
    nullptr
};

static bool isContainerPath(const char* path) {
    if (!path) return false;
    for (int i = 0; CONTAINER_PATHS[i] != nullptr; i++) {
        if (strstr(path, CONTAINER_PATHS[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

static bool shouldFilterMapsLine(const char* line) {
    if (!line) return false;
    if (isContainerPath(line)) return true;
    if (strstr(line, "blackbox") || strstr(line, "BlackBox") ||
        strstr(line, "virtual") || strstr(line, "sandbox")) {
        return true;
    }
    return false;
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_mediateLibraryLoadingNative(JNIEnv*, jobject) {
    LOGD("Mediating library loading...");
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_ensureSignalCompatibilityNative(JNIEnv*, jobject) {
    LOGD("Ensuring signal compatibility...");

    struct sigaction oldSegv{}, oldIll{}, oldTrap{};
    sigaction(SIGSEGV, nullptr, &oldSegv);
    sigaction(SIGILL, nullptr, &oldIll);
    sigaction(SIGTRAP, nullptr, &oldTrap);

    signal(SIGSEGV, SIG_DFL);
    signal(SIGILL, SIG_DFL);
    signal(SIGTRAP, SIG_DFL);

    if (oldSegv.sa_handler != SIG_DFL && oldSegv.sa_handler != SIG_IGN) {
        sigaction(SIGSEGV, &oldSegv, nullptr);
    }
    if (oldIll.sa_handler != SIG_DFL && oldIll.sa_handler != SIG_IGN) {
        sigaction(SIGILL, &oldIll, nullptr);
    }
    if (oldTrap.sa_handler != SIG_DFL && oldTrap.sa_handler != SIG_IGN) {
        sigaction(SIGTRAP, &oldTrap, nullptr);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_virtualizePathsNative(JNIEnv*, jobject) {
    LOGD("Virtualizing paths...");
}

