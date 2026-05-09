
# Create complete NativeSdkProtection.cpp with real hooks
native_sdk_protection_real = '''#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <android/log.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>

// Dobby hook framework (included in BlackBox)
#include "../Dobby/dobby.h"

#define LOG_TAG "SdkProtection"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============ SECURITY SDK SIGNATURES ============
static const char* SECURITY_SDK_LIBS[] = {
    "libanogs.so",
    "libanort.so",
    "libTBlueData.so",
    "libBugly.so",
    "libmsaoaidsec.so",
    "libtup.so",
    "libtsssdk.so",
    "libtersafe.so",
    "libstaysafe.so",
    "libsecuritysdk.so",
    "libsgmain.so",
    "libsgsecuritybody.so",
    "libmobisec.so",
    "libxguardian.so",
    "libantibot.so",
    "libprotect.so",
    "libsafe.so",
    "libhoudini.so",
    "libndk_translation.so",
    nullptr
};

// ============ CONTAINER PATH SIGNATURES ============
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
    "/p0/",
    "/p1/",
    nullptr
};

// ============ SUSPICIOUS PROPERTIES ============
static const char* SUSPICIOUS_PROPS[] = {
    "ro.blackbox",
    "ro.virtual",
    "ro.container",
    "ro.sandbox",
    "persist.blackbox",
    nullptr
};

// ============ ORIGINAL FUNCTION POINTERS ============
static void* (*orig_dlopen)(const char*, int) = nullptr;
static void* (*orig_dlopen_ext)(const char*, int, const android_dlextinfo*) = nullptr;
static int (*orig_sigaction)(int, const struct sigaction*, struct sigaction*) = nullptr;
static int (*orig_sigprocmask)(int, const sigset_t*, sigset_t*) = nullptr;
static FILE* (*orig_fopen)(const char*, const char*) = nullptr;
static int (*orig_open)(const char*, int, ...) = nullptr;
static int (*orig_access)(const char*, int) = nullptr;
static int (*orig_stat)(const char*, struct stat*) = nullptr;
static int (*orig_lstat)(const char*, struct stat*) = nullptr;
static int (*orig_fstat)(int, struct stat*) = nullptr;
static int (*orig___system_property_get)(const char*, char*) = nullptr;
static int (*orig___system_property_read)(const prop_info*, char*, char*) = nullptr;
static ssize_t (*orig_read)(int, void*, size_t) = nullptr;
static ssize_t (*orig_pread)(int, void*, size_t, off_t) = nullptr;

// ============ FILTERED MAPS FILE ============
static int filtered_maps_fd = -1;
static char filtered_maps_path[256] = {0};

/**
 * Check if string contains security SDK name
 */
static bool isSecuritySdk(const char* path) {
    if (!path) return false;
    
    for (int i = 0; SECURITY_SDK_LIBS[i] != nullptr; i++) {
        if (strstr(path, SECURITY_SDK_LIBS[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

/**
 * Check if path contains container signature
 */
static bool isContainerPath(const char* path) {
    if (!path) return false;
    
    for (int i = 0; CONTAINER_PATHS[i] != nullptr; i++) {
        if (strstr(path, CONTAINER_PATHS[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

/**
 * Check if property is suspicious
 */
static bool isSuspiciousProp(const char* name) {
    if (!name) return false;
    
    for (int i = 0; SUSPICIOUS_PROPS[i] != nullptr; i++) {
        if (strstr(name, SUSPICIOUS_PROPS[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

/**
 * Create filtered /proc/self/maps
 * Removes all container-related entries
 */
static bool createFilteredMaps() {
    if (filtered_maps_fd >= 0) {
        close(filtered_maps_fd);
        filtered_maps_fd = -1;
    }
    
    // Read original maps
    int orig_fd = open("/proc/self/maps", O_RDONLY);
    if (orig_fd < 0) {
        LOGE("Failed to open /proc/self/maps");
        return false;
    }
    
    // Create temp file
    snprintf(filtered_maps_path, sizeof(filtered_maps_path), 
             "/data/local/tmp/maps_%d", getpid());
    
    int temp_fd = open(filtered_maps_path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (temp_fd < 0) {
        close(orig_fd);
        return false;
    }
    
    // Read and filter
    char buffer[4096];
    char line[1024];
    int line_pos = 0;
    ssize_t bytes_read;
    
    while ((bytes_read = read(orig_fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\\0';
                
                // Check if line should be filtered
                if (!isContainerPath(line) && 
                    !strstr(line, "blackbox") &&
                    !strstr(line, "BlackBox") &&
                    !strstr(line, "niunaijun") &&
                    !strstr(line, "bcore")) {
                    write(temp_fd, line, line_pos);
                    write(temp_fd, "\\n", 1);
                }
                
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
    }
    
    close(orig_fd);
    close(temp_fd);
    
    // Open for reading
    filtered_maps_fd = open(filtered_maps_path, O_RDONLY);
    
    LOGI("Filtered maps created: %s", filtered_maps_path);
    return filtered_maps_fd >= 0;
}

// ============ HOOKED FUNCTIONS ============

/**
 * Hooked dlopen - Mediate security SDK loading
 */
extern "C" void* hooked_dlopen(const char* filename, int flags) {
    if (filename) {
        LOGD("dlopen: %s", filename);
        
        if (isSecuritySdk(filename)) {
            LOGW("Mediating security SDK: %s", filename);
            
            // Option 1: Block loading (may crash game)
            // return nullptr;
            
            // Option 2: Load but monitor (safer)
            void* handle = orig_dlopen(filename, flags);
            if (handle) {
                LOGI("Security SDK loaded (monitored): %s", filename);
            }
            return handle;
        }
    }
    
    return orig_dlopen(filename, flags);
}

/**
 * Hooked dlopen_ext
 */
extern "C" void* hooked_dlopen_ext(const char* filename, int flags, 
                                    const android_dlextinfo* extinfo) {
    if (filename && isSecuritySdk(filename)) {
        LOGW("Mediating security SDK (ext): %s", filename);
    }
    
    return orig_dlopen_ext(filename, flags, extinfo);
}

/**
 * Hooked sigaction - Monitor security SDK signal handlers
 */
extern "C" int hooked_sigaction(int sig, const struct sigaction* act, 
                                 struct sigaction* oldact) {
    if (sig == SIGSEGV || sig == SIGILL || sig == SIGTRAP || sig == SIGBUS) {
        LOGW("Signal handler setup: sig=%d", sig);
        
        if (act && act->sa_handler != SIG_DFL && act->sa_handler != SIG_IGN) {
            LOGI("Custom signal handler detected for sig=%d", sig);
            
            // Save original handler
            // We could wrap it here for monitoring
        }
    }
    
    return orig_sigaction(sig, act, oldact);
}

/**
 * Hooked sigprocmask
 */
extern "C" int hooked_sigprocmask(int how, const sigset_t* set, sigset_t* oldset) {
    return orig_sigprocmask(how, set, oldset);
}

/**
 * Hooked fopen - Filter sensitive files
 */
extern "C" FILE* hooked_fopen(const char* path, const char* mode) {
    if (path) {
        // Filter /proc/self/maps
        if (strcmp(path, "/proc/self/maps") == 0) {
            LOGD("Filtering /proc/self/maps access");
            
            if (filtered_maps_fd >= 0) {
                // Return filtered version
                close(filtered_maps_fd);
                filtered_maps_fd = open(filtered_maps_path, O_RDONLY);
                if (filtered_maps_fd >= 0) {
                    return fdopen(filtered_maps_fd, mode);
                }
            }
        }
        
        // Filter container paths
        if (isContainerPath(path)) {
            LOGW("Hiding container path: %s", path);
            errno = ENOENT;
            return nullptr;
        }
    }
    
    return orig_fopen(path, mode);
}

/**
 * Hooked open - Filter sensitive files
 */
extern "C" int hooked_open(const char* pathname, int flags, ...) {
    if (pathname) {
        // Filter /proc/self/maps
        if (strcmp(pathname, "/proc/self/maps") == 0) {
            LOGD("Filtering /proc/self/maps via open()");
            
            if (filtered_maps_fd >= 0) {
                close(filtered_maps_fd);
            }
            
            filtered_maps_fd = open(filtered_maps_path, flags);
            if (filtered_maps_fd >= 0) {
                return filtered_maps_fd;
            }
        }
        
        // Filter container paths
        if (isContainerPath(pathname)) {
            LOGW("Hiding container path via open(): %s", pathname);
            errno = ENOENT;
            return -1;
        }
    }
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    return orig_open(pathname, flags, mode);
}

/**
 * Hooked access - Hide container paths
 */
extern "C" int hooked_access(const char* pathname, int mode) {
    if (pathname && isContainerPath(pathname)) {
        LOGW("Hiding container path via access(): %s", pathname);
        errno = ENOENT;
        return -1;
    }
    
    return orig_access(pathname, mode);
}

/**
 * Hooked stat - Hide container paths
 */
extern "C" int hooked_stat(const char* pathname, struct stat* statbuf) {
    if (pathname && isContainerPath(pathname)) {
        LOGW("Hiding container path via stat(): %s", pathname);
        errno = ENOENT;
        return -1;
    }
    
    return orig_stat(pathname, statbuf);
}

/**
 * Hooked __system_property_get - Filter suspicious props
 */
extern "C" int hooked___system_property_get(const char* name, char* value) {
    int result = orig___system_property_get(name, value);
    
    if (name && isSuspiciousProp(name)) {
        LOGW("Filtering suspicious property: %s", name);
        if (value) {
            value[0] = '\\0';
        }
        return 0;
    }
    
    return result;
}

// ============ JNI METHODS ============

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_mediateLibraryLoadingNative(
    JNIEnv* env, jobject thiz) {
    
    LOGI("Installing library loading hooks...");
    
    // Hook dlopen
    void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    if (dlopen_addr) {
        if (DobbyHook(dlopen_addr, (void*)hooked_dlopen, (void**)&orig_dlopen) == 0) {
            LOGI("dlopen hooked");
        } else {
            LOGE("Failed to hook dlopen");
        }
    }
    
    // Hook dlopen_ext (Android specific)
    void* dlopen_ext_addr = dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (dlopen_ext_addr) {
        if (DobbyHook(dlopen_ext_addr, (void*)hooked_dlopen_ext, (void**)&orig_dlopen_ext) == 0) {
            LOGI("dlopen_ext hooked");
        }
    }
    
    LOGI("Library loading hooks installed");
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_ensureSignalCompatibilityNative(
    JNIEnv* env, jobject thiz) {
    
    LOGI("Installing signal compatibility hooks...");
    
    // Hook sigaction
    void* sigaction_addr = dlsym(RTLD_DEFAULT, "sigaction");
    if (sigaction_addr) {
        if (DobbyHook(sigaction_addr, (void*)hooked_sigaction, (void**)&orig_sigaction) == 0) {
            LOGI("sigaction hooked");
        } else {
            LOGE("Failed to hook sigaction");
        }
    }
    
    // Hook sigprocmask
    void* sigprocmask_addr = dlsym(RTLD_DEFAULT, "sigprocmask");
    if (sigprocmask_addr) {
        if (DobbyHook(sigprocmask_addr, (void*)hooked_sigprocmask, (void**)&orig_sigprocmask) == 0) {
            LOGI("sigprocmask hooked");
        }
    }
    
    LOGI("Signal compatibility hooks installed");
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_security_SdkProtectionManager_virtualizePathsNative(
    JNIEnv* env, jobject thiz) {
    
    LOGI("Installing path virtualization hooks...");
    
    // Create filtered maps
    if (!createFilteredMaps()) {
        LOGW("Failed to create filtered maps");
    }
    
    // Hook fopen
    void* fopen_addr = dlsym(RTLD_DEFAULT, "fopen");
    if (fopen_addr) {
        if (DobbyHook(fopen_addr, (void*)hooked_fopen, (void**)&orig_fopen) == 0) {
            LOGI("fopen hooked");
        } else {
            LOGE("Failed to hook fopen");
        }
    }
    
    // Hook open
    void* open_addr = dlsym(RTLD_DEFAULT, "open");
    if (open_addr) {
        if (DobbyHook(open_addr, (void*)hooked_open, (void**)&orig_open) == 0) {
            LOGI("open hooked");
        } else {
            LOGE("Failed to hook open");
        }
    }
    
    // Hook access
    void* access_addr = dlsym(RTLD_DEFAULT, "access");
    if (access_addr) {
        if (DobbyHook(access_addr, (void*)hooked_access, (void**)&orig_access) == 0) {
            LOGI("access hooked");
        }
    }
    
    // Hook stat
    void* stat_addr = dlsym(RTLD_DEFAULT, "stat");
    if (stat_addr) {
        if (DobbyHook(stat_addr, (void*)hooked_stat, (void**)&orig_stat) == 0) {
            LOGI("stat hooked");
        }
    }
    
    // Hook __system_property_get
    void* prop_get_addr = dlsym(RTLD_DEFAULT, "__system_property_get");
    if (prop_get_addr) {
        if (DobbyHook(prop_get_addr, (void*)hooked___system_property_get, 
                      (void**)&orig___system_property_get) == 0) {
            LOGI("__system_property_get hooked");
        }
    }
    
    LOGI("Path virtualization hooks installed");
}

// ============ INIT ============

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("NativeSdkProtection loaded - Real Hook Version");
    return JNI_VERSION_1_6;
}
'''

with open('/mnt/agents/output/NativeSdkProtection_Real.cpp', 'w', encoding='utf-8') as f:
    f.write(native_sdk_protection_real)

print("✅ NativeSdkProtection_Real.cpp created with REAL hooks!")
print(f"Size: {len(native_sdk_protection_real)} chars")
