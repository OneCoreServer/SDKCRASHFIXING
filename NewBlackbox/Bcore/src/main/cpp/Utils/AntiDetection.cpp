#include <android/log.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <stdarg.h>
#include <dlfcn.h>
#include "Dobby/dobby.h"
#include "xdl.h"

#define LOG_TAG "AntiDetection"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* blocked_files[] = {
    // su binaries
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/xbin/daemonsu",
    "/system/xbin/sugote",
    "/system/bin/sugote-mksh",
    "/system/xbin/sugote-mksh",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/tmp/su",
    "/system/bin/magisk",
    "/system/xbin/magisk",
    "/sbin/magisk",
    "/data/adb/magisk",
    // Virtual environments
    "/data/virtual",
    "/data/data/com.benny.openlauncher",
    "/data/data/io.va.exposed",
    "/data/data/com.lody.virtual",
    "/data/data/com.excelliance.dualaid",
    "/data/data/com.lbe.parallel",
    "/data/data/com.dual.dualspace",
    "/data/data/com.ludashi.superboost",
    "/data/data/top.niunaijun.blackboxa",
    "/blackbox",
    "/virtual",
    // Emulators
    "/dev/vboxguest",
    "/dev/vboxuser",
    "/dev/qemu_pipe",
    "/dev/goldfish_pipe",
    "/dev/socket/qemud",
    "/dev/socket/baseband_genyd",
    "/dev/socket/genyd",
    "/system/lib/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace",
    "/system/bin/qemu-props",
    "/system/bin/nox-prop",
    "/sys/module/goldfish_audio",
    "/sys/module/goldfish_sync",
    "/proc/tty/drivers/goldfish",
    "/dev/goldfish_events",
    "/system/lib/libdroid4x.so",
    "/system/bin/windroyed",
    "/system/lib/libnoxspeedup.so",
    "/system/lib/libmemu.so",
    "/system/lib/libbluelog.so",
    // Xposed
    "/system/xposed.prop",
    "/system/framework/XposedBridge.jar",
    "/data/data/de.robv.android.xposed.installer",
    "/data/data/org.meowcat.edxposed.manager",
    "/data/data/top.canyie.dreamland.manager",
    nullptr
};

static const char* blocked_packages[] = {
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite", 
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.zachspong.temprootremovejb",
    "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootPremium",
    "com.formyhm.hideroot",
    "me.phh.superuser",
    "eu.chainfire.supersu.pro",
    "com.kingouser.com",
    "com.topjohnwu.magisk",
    "com.lody.virtual",
    "io.va.exposed",
    "com.benny.openlauncher",
    nullptr
};

static bool is_blocked_file(const char* path) {
    if (!path) return false;
    for (int i = 0; blocked_files[i]; ++i) {
        if (strstr(path, blocked_files[i])) {
            return true;
        }
    }
    return false;
}

static bool is_blocked_package(const char* path) {
    if (!path) return false;
    for (int i = 0; blocked_packages[i]; ++i) {
        if (strstr(path, blocked_packages[i])) {
            return true;
        }
    }
    return false;
}

// Original function pointers for file hooks
static int (*orig_access)(const char *pathname, int mode) = nullptr;
static int (*orig_stat)(const char *pathname, struct stat *buf) = nullptr;
static int (*orig_lstat)(const char *pathname, struct stat *buf) = nullptr;
static FILE* (*orig_fopen)(const char *pathname, const char *mode) = nullptr;
static int (*orig_open)(const char *pathname, int flags, ...) = nullptr;
static ssize_t (*orig_readlink)(const char *pathname, char *buf, size_t bufsiz) = nullptr;
static DIR* (*orig_opendir)(const char *name) = nullptr;

// Original ptrace function pointer
static long (*orig_ptrace)(int request, pid_t pid, void *addr, void *data) = nullptr;

static bool is_safe_path(const char* path) {
    if (!path) return false;
    if (strstr(path, "/proc/net/")) return true;
    if (strstr(path, "/dev/socket/")) return true;
    return false;
}

// Hook implementations for file functions
static int my_access(const char *pathname, int mode) {
    if (pathname && !is_safe_path(pathname) && (is_blocked_file(pathname) || is_blocked_package(pathname))) {
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(pathname, mode) : -1;
}

static int my_stat(const char *pathname, struct stat *buf) {
    if (pathname && !is_safe_path(pathname) && (is_blocked_file(pathname) || is_blocked_package(pathname))) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(pathname, buf) : -1;
}

static int my_lstat(const char *pathname, struct stat *buf) {
    if (pathname && !is_safe_path(pathname) && (is_blocked_file(pathname) || is_blocked_package(pathname))) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(pathname, buf) : -1;
}

static FILE* my_fopen(const char *pathname, const char *mode) {
    if (pathname && !is_safe_path(pathname) && (is_blocked_file(pathname) || is_blocked_package(pathname))) {
        errno = ENOENT;
        return nullptr;
    }
    return orig_fopen ? orig_fopen(pathname, mode) : nullptr;
}

static int my_open(const char *pathname, int flags, ...) {
    if (pathname && !is_safe_path(pathname) && (is_blocked_file(pathname) || is_blocked_package(pathname))) {
        errno = ENOENT;
        return -1;
    }
    if (orig_open) {
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode_t mode = va_arg(args, mode_t);
            va_end(args);
            return orig_open(pathname, flags, mode);
        } else {
            return orig_open(pathname, flags);
        }
    }
    return -1;
}

static ssize_t my_readlink(const char *pathname, char *buf, size_t bufsiz) {
    if (pathname && !is_safe_path(pathname) && (is_blocked_file(pathname) || is_blocked_package(pathname))) {
        errno = ENOENT;
        return -1;
    }
    return orig_readlink ? orig_readlink(pathname, buf, bufsiz) : -1;
}

static DIR* my_opendir(const char *name) {
    if (name && !is_safe_path(name) && (is_blocked_file(name) || is_blocked_package(name))) {
        errno = ENOENT;
        return nullptr;
    }
    return orig_opendir ? orig_opendir(name) : nullptr;
}

// Ptrace hook implementation
static long my_ptrace(int request, pid_t pid, void *addr, void *data) {
    if (request == PTRACE_TRACEME) {
        LOGD("Bypassing ptrace(PTRACE_TRACEME, ...)");
        return 0;  // Always success
    }
    if (orig_ptrace) {
        return orig_ptrace(request, pid, addr, data);
    }
    return -1;
}

// Helper to get symbol address using xdl
static void* get_sym(const char* lib, const char* sym) {
    void* handle = xdl_open(lib, XDL_DEFAULT);
    if (!handle) return nullptr;
    void* addr = xdl_sym(handle, sym, nullptr);
    xdl_close(handle);
    return addr;
}

static void install_file_hooks() {
    LOGD("Installing file system hooks...");

    // Get original libc addresses
    orig_access = (int (*)(const char*, int)) get_sym("libc.so", "access");
    orig_stat = (int (*)(const char*, struct stat*)) get_sym("libc.so", "stat");
    orig_lstat = (int (*)(const char*, struct stat*)) get_sym("libc.so", "lstat");
    orig_fopen = (FILE* (*)(const char*, const char*)) get_sym("libc.so", "fopen");
    orig_open = (int (*)(const char*, int, ...)) get_sym("libc.so", "open");
    orig_readlink = (ssize_t (*)(const char*, char*, size_t)) get_sym("libc.so", "readlink");
    orig_opendir = (DIR* (*)(const char*)) get_sym("libc.so", "opendir");

    // Install hooks using Dobby
    if (orig_access) DobbyHook((void*)orig_access, (void*)my_access, (void**)&orig_access);
    if (orig_stat) DobbyHook((void*)orig_stat, (void*)my_stat, (void**)&orig_stat);
    if (orig_lstat) DobbyHook((void*)orig_lstat, (void*)my_lstat, (void**)&orig_lstat);
    if (orig_fopen) DobbyHook((void*)orig_fopen, (void*)my_fopen, (void**)&orig_fopen);
    if (orig_open) DobbyHook((void*)orig_open, (void*)my_open, (void**)&orig_open);
    if (orig_readlink) DobbyHook((void*)orig_readlink, (void*)my_readlink, (void**)&orig_readlink);
    if (orig_opendir) DobbyHook((void*)orig_opendir, (void*)my_opendir, (void**)&orig_opendir);

    LOGD("File system hooks installed successfully");
}

static void install_ptrace_hook() {
    void* ptrace_addr = dlsym(RTLD_DEFAULT, "ptrace");
    if (ptrace_addr) {
        // Save original and hook
        orig_ptrace = (long (*)(int, pid_t, void*, void*)) ptrace_addr;
        DobbyHook(ptrace_addr, (void*)my_ptrace, (void**)&orig_ptrace);
        LOGD("ptrace hook installed successfully");
    } else {
        LOGE("Failed to find ptrace symbol");
    }
}

__attribute__((constructor)) void install_antidetection_hooks() {
    LOGD("Installing anti-detection hooks...");
    install_file_hooks();
    install_ptrace_hook();
    LOGD("Anti-detection hooks installation complete");
}
