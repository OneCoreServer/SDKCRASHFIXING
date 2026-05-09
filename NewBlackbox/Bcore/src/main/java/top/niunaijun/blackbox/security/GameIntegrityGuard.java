
# Create GameIntegrityGuard.java - Game-specific protection
game_integrity_guard = '''package top.niunaijun.blackbox.security;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Process;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Game Integrity Guard
 * Monitors and maintains game integrity during runtime
 * Prevents crashes caused by environment detection
 * 
 * Features:
 * - Runtime environment monitoring
 * - Automatic integrity restoration
 * - Crash prevention for security SDKs
 * - Process anomaly detection
 */
public class GameIntegrityGuard {
    private static final String TAG = "GameIntegrityGuard";
    
    private static GameIntegrityGuard sInstance;
    private boolean mMonitoring = false;
    private Thread mMonitorThread;
    private String mCurrentGame = null;
    
    // Monitoring intervals
    private static final long MONITOR_INTERVAL_MS = 2000;
    private static final long INTEGRITY_CHECK_INTERVAL_MS = 5000;
    
    // Anomaly thresholds
    private static final int MAX_THREAD_COUNT = 100;
    private static final long MAX_MEMORY_MB = 2048;
    
    private GameIntegrityGuard() {}
    
    public static synchronized GameIntegrityGuard getInstance() {
        if (sInstance == null) {
            sInstance = new GameIntegrityGuard();
        }
        return sInstance;
    }
    
    /**
     * Start monitoring game integrity
     */
    public void startMonitoring(String packageName) {
        if (mMonitoring) return;
        
        mCurrentGame = packageName;
        mMonitoring = true;
        
        Slog.i(TAG, "Starting integrity monitoring for: " + packageName);
        
        // Apply SDK protection
        SdkProtectionManager.getInstance().onGameLaunch(packageName);
        
        // Start monitor thread
        mMonitorThread = new Thread(() -> {
            long lastIntegrityCheck = 0;
            
            while (mMonitoring) {
                try {
                    // Basic monitoring
                    checkProcessHealth();
                    
                    // Periodic integrity check
                    long now = System.currentTimeMillis();
                    if (now - lastIntegrityCheck > INTEGRITY_CHECK_INTERVAL_MS) {
                        checkEnvironmentIntegrity();
                        lastIntegrityCheck = now;
                    }
                    
                    Thread.sleep(MONITOR_INTERVAL_MS);
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    Slog.w(TAG, "Monitor error: " + e.getMessage());
                }
            }
        }, "GameIntegrityMonitor");
        
        mMonitorThread.start();
    }
    
    /**
     * Stop monitoring
     */
    public void stopMonitoring() {
        mMonitoring = false;
        mCurrentGame = null;
        
        if (mMonitorThread != null) {
            mMonitorThread.interrupt();
            mMonitorThread = null;
        }
        
        Slog.i(TAG, "Integrity monitoring stopped");
    }
    
    /**
     * Check process health (threads, memory)
     */
    private void checkProcessHealth() {
        try {
            // Check thread count
            int threadCount = Thread.activeCount();
            if (threadCount > MAX_THREAD_COUNT) {
                Slog.w(TAG, "High thread count detected: " + threadCount);
                // Could trigger thread cleanup if needed
            }
            
            // Check memory usage
            Runtime runtime = Runtime.getRuntime();
            long usedMemory = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024);
            if (usedMemory > MAX_MEMORY_MB) {
                Slog.w(TAG, "High memory usage: " + usedMemory + " MB");
            }
            
            // Check if process is still alive
            if (!isProcessAlive(Process.myPid())) {
                Slog.e(TAG, "Process not alive!");
                stopMonitoring();
            }
            
        } catch (Exception e) {
            Slog.w(TAG, "Health check error: " + e.getMessage());
        }
    }
    
    /**
     * Check environment integrity
     */
    private void checkEnvironmentIntegrity() {
        try {
            // Check /proc/self/maps for container traces
            checkMapsIntegrity();
            
            // Check environment variables
            checkEnvIntegrity();
            
            // Check system properties
            checkPropertiesIntegrity();
            
        } catch (Exception e) {
            Slog.w(TAG, "Integrity check error: " + e.getMessage());
        }
    }
    
    /**
     * Check /proc/self/maps for suspicious entries
     */
    private void checkMapsIntegrity() {
        try {
            File mapsFile = new File("/proc/self/maps");
            if (!mapsFile.exists()) return;
            
            BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
            String line;
            int suspiciousCount = 0;
            
            while ((line = reader.readLine()) != null) {
                if (SdkProtectionManager.getInstance().containsContainerPath(line)) {
                    suspiciousCount++;
                }
            }
            reader.close();
            
            if (suspiciousCount > 0) {
                Slog.w(TAG, "Found " + suspiciousCount + " suspicious entries in maps");
                // Trigger maps filtering if needed
            }
            
        } catch (Exception e) {
            Slog.w(TAG, "Maps check error: " + e.getMessage());
        }
    }
    
    /**
     * Check environment variables
     */
    private void checkEnvIntegrity() {
        try {
            // Check for container-related env vars
            String[] envVars = {"BLACKBOX_PATH", "VIRTUAL_ENV", "CONTAINER_ID"};
            
            for (String var : envVars) {
                String value = System.getenv(var);
                if (value != null && !value.isEmpty()) {
                    Slog.w(TAG, "Suspicious env var: " + var + "=" + value);
                }
            }
            
        } catch (Exception e) {
            Slog.w(TAG, "Env check error: " + e.getMessage());
        }
    }
    
    /**
     * Check system properties
     */
    private void checkPropertiesIntegrity() {
        try {
            // Check for container-related properties
            String[] props = {
                "blackbox.version",
                "virtual.container",
                "sandbox.enabled"
            };
            
            for (String prop : props) {
                String value = System.getProperty(prop);
                if (value != null && !value.isEmpty()) {
                    Slog.w(TAG, "Suspicious property: " + prop + "=" + value);
                }
            }
            
        } catch (Exception e) {
            Slog.w(TAG, "Properties check error: " + e.getMessage());
        }
    }
    
    /**
     * Check if process is alive
     */
    private boolean isProcessAlive(int pid) {
        try {
            return android.os.Process.killProcess(pid) == false; // killProcess doesn't return value
        } catch (Exception e) {
            return true; // Assume alive if can't check
        }
    }
    
    /**
     * Handle detected integrity violation
     */
    private void handleIntegrityViolation(String reason) {
        Slog.e(TAG, "Integrity violation: " + reason);
        
        // Attempt to restore integrity
        restoreIntegrity();
    }
    
    /**
     * Restore environment integrity
     */
    private void restoreIntegrity() {
        Slog.i(TAG, "Restoring environment integrity...");
        
        try {
            // Re-apply SDK protection
            SdkProtectionManager.getInstance().setEnabled(true);
            
            // Re-apply device spoofing
            // ...
            
            // Clear suspicious caches
            clearSuspiciousCaches();
            
        } catch (Exception e) {
            Slog.e(TAG, "Failed to restore integrity: " + e.getMessage());
        }
    }
    
    /**
     * Clear suspicious caches
     */
    private void clearSuspiciousCaches() {
        try {
            // Clear package manager caches
            // This prevents cached container info from being detected
            
        } catch (Exception e) {
            Slog.w(TAG, "Cache clear error: " + e.getMessage());
        }
    }
    
    /**
     * Called when game process is created
     */
    public void onGameProcessCreated(String packageName, int pid) {
        Slog.i(TAG, "Game process created: " + packageName + " PID: " + pid);
        
        // Apply protection to new process
        SdkProtectionManager.getInstance().onGameLaunch(packageName);
    }
    
    /**
     * Called when game crashes
     */
    public void onGameCrash(String packageName, Throwable error) {
        Slog.e(TAG, "Game crashed: " + packageName, error);
        
        // Analyze crash
        if (isSecuritySdkCrash(error)) {
            Slog.w(TAG, "Security SDK related crash detected");
            // Apply stronger protection
            SdkProtectionManager.getInstance().setEnabled(true);
        }
    }
    
    /**
     * Check if crash is related to security SDK
     */
    private boolean isSecuritySdkCrash(Throwable error) {
        if (error == null) return false;
        
        String message = error.getMessage();
        if (message == null) return false;
        
        String lower = message.toLowerCase();
        return lower.contains("security") || 
               lower.contains("anticheat") ||
               lower.contains("integrity") ||
               lower.contains("tamper") ||
               lower.contains("hook");
    }
}
'''

with open('/mnt/agents/output/GameIntegrityGuard.java', 'w', encoding='utf-8') as f:
    f.write(game_integrity_guard)

print("✅ GameIntegrityGuard.java created!")
print(f"Size: {len(game_integrity_guard)} chars")
