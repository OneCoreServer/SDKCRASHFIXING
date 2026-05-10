#include "FileSystemHook.h"
#include <IO.h>
#include <BoxCore.h>
#include "UnixFileSystemHook.h"
#import "JniHook/JniHook.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "Dobby/dobby.h"

// Original open/open64 functions (already defined in UnixFileSystemHook)
static int (*orig_open)(const char *pathname, int flags, ...) = nullptr;
static int (*orig_open64)(const char *pathname, int flags, ...) = nullptr;

// Helper: create filtered /proc/self/maps
static int create_fake_maps(int flags, mode_t mode) {
    FILE *original = fopen("/proc/self/maps", "r");
    if (!original) return -1;

    char temp_path[256];
    snprintf(temp_path, sizeof(temp_path), "/data/user/0/top.niunaijun.blackboxa/cache/fake_maps_%d", getpid());
    FILE *fake = fopen(temp_path, "w");
    if (!fake) {
        fclose(original);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), original)) {
        // Filter out blackbox-related libraries
        if (strstr(line, "blackbox") != nullptr ||
            strstr(line, "libdobby.so") != nullptr ||
            strstr(line, "niunaijun") != nullptr ||
            strstr(line, "xdl") != nullptr ||
            strstr(line, "libxposed.so") != nullptr ||
            strstr(line, "lspatch") != nullptr) {
            continue; // hide from game
        }
        fputs(line, fake);
    }

    fclose(original);
    fclose(fake);

    // Return fd of filtered file using original open
    return orig_open(temp_path, flags, mode);
}

// Hook for open()
int new_open(const char *pathname, int flags, ...) {
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);

    if (pathname != nullptr) {
        // Intercept /proc/self/maps
        if (strcmp(pathname, "/proc/self/maps") == 0 || strcmp(pathname, "/proc/self/smaps") == 0) {
            ALOGD("FileSystemHook: Filtering maps for Anti-Cheat");
            return create_fake_maps(flags, mode);
        }

        // Existing block list (if any)
        if (strstr(pathname, "resource-cache") != nullptr ||
            strstr(pathname, "@idmap") != nullptr ||
            strstr(pathname, ".frro") != nullptr ||
            strstr(pathname, "data@resource-cache@") != nullptr) {
            errno = ENOENT;
            return -1;
        }
    }

    return orig_open(pathname, flags, mode);
}

// Hook for open64 (same logic)
int new_open64(const char *pathname, int flags, ...) {
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);

    if (pathname != nullptr) {
        if (strcmp(pathname, "/proc/self/maps") == 0 || strcmp(pathname, "/proc/self/smaps") == 0) {
            ALOGD("FileSystemHook: Filtering maps for Anti-Cheat (open64)");
            return create_fake_maps(flags, mode);
        }

        if (strstr(pathname, "resource-cache") != nullptr ||
            strstr(pathname, "@idmap") != nullptr ||
            strstr(pathname, ".frro") != nullptr ||
            strstr(pathname, "data@resource-cache@") != nullptr) {
            errno = ENOENT;
            return -1;
        }
    }

    return orig_open64(pathname, flags, mode);
}

// Install hooks
void FileSystemHook::init() {
    ALOGD("FileSystemHook::init: Installing open/open64 hooks with maps filter");

    // Get original open function pointer
    void *open_addr = dlsym(RTLD_DEFAULT, "open");
    if (open_addr) {
        DobbyHook(open_addr, (void *)new_open, (void **)&orig_open);
        ALOGD("FileSystemHook: open hooked");
    } else {
        ALOGE("FileSystemHook: failed to find open");
    }

    void *open64_addr = dlsym(RTLD_DEFAULT, "open64");
    if (open64_addr) {
        DobbyHook(open64_addr, (void *)new_open64, (void **)&orig_open64);
        ALOGD("FileSystemHook: open64 hooked");
    } else {
        ALOGE("FileSystemHook: failed to find open64");
    }
}
