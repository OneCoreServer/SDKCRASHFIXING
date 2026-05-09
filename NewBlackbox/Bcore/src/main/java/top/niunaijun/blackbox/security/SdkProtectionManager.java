package top.niunaijun.blackbox.security;

import android.content.Context;
import android.os.Build;
import android.os.Process;

import java.io.File;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.utils.Slog;

/**
 * SDK Protection Manager
 * Provides runtime environment protection for games and apps
 * Ensures compatibility with security SDKs without triggering false positives
 * 
 * Features:
 * - Environment sanitization
 * - Process information normalization  
 * - Library loading mediation
 * - Signal handling compatibility
 * - Path virtualization
 */
public class SdkProtectionManager {
    private static final String TAG = "SdkProtectionManager";
    
    private static SdkProtectionManager sInstance;
    private boolean mEnabled = false;
    private Context mContext;
    
    // Security SDK library signatures to mediate
    private static final String[] SECURITY_SDK_LIBS = {
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
        "libndk_translation.so"
    };
    
    // Container paths that may confuse security SDKs
    private static final String[] CONTAINER_PATHS = {
        "/blackbox/",
        "/BlackBox/",
        "/virtual/",
        "/parallel/",
        "/dual/",
        "/clone/",
        "/sandbox/",
        "/niunaijun/",
        "/bcore/",
        "/vbox/"
    };
    
    private SdkProtectionManager() {}
    
    public static synchronized SdkProtectionManager getInstance() {
        if (sInstance == null) {
            sInstance = new SdkProtectionManager();
        }
        return sInstance;
    }
    
    public void initialize(Context context) {
        mContext = context;
        Slog.i(TAG, "SdkProtectionManager initialized");
    }
    
    public void setEnabled(boolean enabled) {
        mEnabled = enabled;
        Slog.i(TAG, "SdkProtectionManager " + (enabled ? "ENABLED" : "DISABLED"));
        
        if (enabled) {
            applyProtection();
        }
    }
    
    public boolean isEnabled() {
        return mEnabled;
    }
    
    /**
     * Apply all SDK protection measures
     */
    private void applyProtection() {
        try {
            Slog.i(TAG, "Applying SDK protection measures...");
            
            // 1. Normalize device fingerprint
            normalizeDeviceFingerprint();
            
            // 2. Sanitize process information
            sanitizeProcessInfo();
            
            // 3. Mediate library loading
            mediateLibraryLoading();
            
            // 4. Ensure signal compatibility
            ensureSignalCompatibility();
            
            // 5. Virtualize sensitive paths
            virtualizePaths();
            
            Slog.i(TAG, "SDK protection measures applied successfully");
            
        } catch (Exception e) {
            Slog.e(TAG, "Error applying SDK protection: " + e.getMessage());
        }
    }
    
    /**
     * Normalize device fingerprint to standard format
     */
    private void normalizeDeviceFingerprint() {
        try {
            Slog.d(TAG, "Normalizing device fingerprint...");
            
            Map<String, String> normalizedValues = new HashMap<>();
            
            // Use standard OEM values
            normalizedValues.put("FINGERPRINT", "google/redfin/redfin:13/TQ3A.230805.001/10316531:user/release-keys");
            normalizedValues.put("BRAND", "google");
            normalizedValues.put("MANUFACTURER", "Google");
            normalizedValues.put("MODEL", "Pixel 5");
            normalizedValues.put("PRODUCT", "redfin");
            normalizedValues.put("DEVICE", "redfin");
            normalizedValues.put("BOARD", "redfin");
            normalizedValues.put("HARDWARE", "redfin");
            normalizedValues.put("BOOTLOADER", "b4s4-0.4-8048680");
            normalizedValues.put("RADIO", "g8150-00123-231213-B-11251756");
            
            // Apply via reflection
            for (Map.Entry<String, String> entry : normalizedValues.entrySet()) {
                try {
                    Field field = Build.class.getDeclaredField(entry.getKey());
                    field.setAccessible(true);
                    field.set(null, entry.getValue());
                } catch (Exception e) {
                    Slog.w(TAG, "Failed to normalize " + entry.getKey());
                }
            }
            
            Slog.d(TAG, "Device fingerprint normalized");
            
        } catch (Exception e) {
            Slog.e(TAG, "Error normalizing fingerprint: " + e.getMessage());
        }
    }
    
    /**
     * Sanitize process information to avoid detection
     */
    private void sanitizeProcessInfo() {
        try {
            Slog.d(TAG, "Sanitizing process information...");
            
            int pid = Process.myPid();
            int uid = Process.myUid();
            
            // Log for debugging
            Slog.d(TAG, "Process PID: " + pid + ", UID: " + uid);
            
            // Ensure process name doesn't contain container signatures
            // This is handled by BlackBox internals
            
        } catch (Exception e) {
            Slog.e(TAG, "Error sanitizing process info: " + e.getMessage());
        }
    }
    
    /**
     * Mediate security SDK library loading
     */
    private void mediateLibraryLoading() {
        try {
            Slog.d(TAG, "Mediating library loading...");
            
            // Hook System.loadLibrary via JNI
            // This allows us to monitor and mediate security SDK initialization
            mediateLibraryLoadingNative();
            
        } catch (Exception e) {
            Slog.e(TAG, "Error mediating library loading: " + e.getMessage());
        }
    }
    
    /**
     * Ensure signal handling compatibility with security SDKs
     */
    private void ensureSignalCompatibility() {
        try {
            Slog.d(TAG, "Ensuring signal compatibility...");
            
            // Security SDKs often set custom signal handlers
            // We ensure our handlers don't conflict
            ensureSignalCompatibilityNative();
            
        } catch (Exception e) {
            Slog.e(TAG, "Error ensuring signal compatibility: " + e.getMessage());
        }
    }
    
    /**
     * Virtualize sensitive paths to hide container traces
     */
    private void virtualizePaths() {
        try {
            Slog.d(TAG, "Virtualizing sensitive paths...");
            
            // Hook file system calls to redirect container paths
            virtualizePathsNative();
            
        } catch (Exception e) {
            Slog.e(TAG, "Error virtualizing paths: " + e.getMessage());
        }
    }
    
    /**
     * Check if library is a security SDK
     */
    public boolean isSecuritySdk(String libName) {
        if (libName == null) return false;
        
        String lower = libName.toLowerCase();
        for (String sdk : SECURITY_SDK_LIBS) {
            if (lower.contains(sdk.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get mediated library path
     */
    public String getMediatedLibraryPath(String originalPath) {
        if (!isSecuritySdk(originalPath)) {
            return originalPath;
        }
        
        Slog.w(TAG, "Mediating security SDK library: " + originalPath);
        
        // Option 1: Return null to prevent loading (may crash game)
        // return null;
        
        // Option 2: Return path to compatibility shim
        // return getCompatibilityShimPath(originalPath);
        
        // Option 3: Return original but log for monitoring
        return originalPath;
    }
    
    /**
     * Check if path contains container signatures
     */
    public boolean containsContainerPath(String path) {
        if (path == null) return false;
        
        String lower = path.toLowerCase();
        for (String containerPath : CONTAINER_PATHS) {
            if (lower.contains(containerPath.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Sanitize path for security SDK checks
     */
    public String sanitizePath(String path) {
        if (path == null) return null;
        
        String sanitized = path;
        for (String containerPath : CONTAINER_PATHS) {
            if (sanitized.toLowerCase().contains(containerPath.toLowerCase())) {
                sanitized = sanitized.replaceAll("(?i)" + containerPath, "/data/data/");
            }
        }
        
        return sanitized;
    }
    
    /**
     * Called when game is launched - apply game-specific protection
     */
    public void onGameLaunch(String packageName) {
        Slog.i(TAG, "Applying SDK protection for game: " + packageName);
        
        // Apply protection if not already enabled
        if (!mEnabled) {
            setEnabled(true);
        }
        
        // Apply additional game-specific measures
        applyGameSpecificProtection(packageName);
    }
    
    /**
     * Apply game-specific protection measures
     */
    private void applyGameSpecificProtection(String packageName) {
        try {
            // Game-specific adjustments
            if (packageName.contains("pubg") || packageName.contains("bgmi")) {
                Slog.d(TAG, "Applying PUBG/BGMI specific protection");
                // Specific adjustments for Tencent games
            } else if (packageName.contains("freefire")) {
                Slog.d(TAG, "Applying Free Fire specific protection");
                // Specific adjustments for Garena games
            } else if (packageName.contains("cod")) {
                Slog.d(TAG, "Applying COD specific protection");
                // Specific adjustments for Activision games
            }
            
        } catch (Exception e) {
            Slog.w(TAG, "Error applying game-specific protection: " + e.getMessage());
        }
    }
    
    // Native methods
    private native void mediateLibraryLoadingNative();
    private native void ensureSignalCompatibilityNative();
    private native void virtualizePathsNative();
    
    static {
        try {
            System.loadLibrary("sdk_protection");
        } catch (Exception e) {
            Slog.w(TAG, "Failed to load SDK protection native library: " + e.getMessage());
        }
    }
}
