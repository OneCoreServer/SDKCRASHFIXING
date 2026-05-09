package com.onecore.loader.utils;

import android.content.Context;
import android.util.Log;

import com.onecore.loader.BuildConfig;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class FLog {
    public static final String TAG = FLog.class.getSimpleName();
    private static File logFile;
    private static final Object LOCK = new Object();

    public static void init(Context context) {
        if (context == null) return;
        synchronized (LOCK) {
            if (logFile != null) return;
            File dir = new File(context.getFilesDir(), "logs");
            if (!dir.exists() && !dir.mkdirs()) {
                Log.e(TAG, "Failed to create log dir: " + dir.getAbsolutePath());
                return;
            }
            logFile = new File(dir, "loader-debug.log");
            try {
                if (!logFile.exists()) {
                    logFile.createNewFile();
                }
            } catch (IOException e) {
                Log.e(TAG, "Failed to create log file: " + e.getMessage());
            }
            writeToFile("INFO", "FLog initialized. Log path: " + logFile.getAbsolutePath());
        }
    }

    public static String getLogFilePath() {
        return logFile != null ? logFile.getAbsolutePath() : "not_initialized";
    }

    public static void debug(String msg) {
        if (BuildConfig.DEBUG) {
            Log.d(TAG, msg);
        }
        writeToFile("DEBUG", msg);
    }

    public static void info(String msg) {
        if (BuildConfig.DEBUG) {
            Log.i(TAG, msg);
        }
        writeToFile("INFO", msg);
    }

    public static void warning(String msg) {
        if (BuildConfig.DEBUG) {
            Log.w(TAG, msg);
        }
        writeToFile("WARN", msg);
    }

    public static void error(String msg) {
        if (BuildConfig.DEBUG) {
            Log.e(TAG, msg);
        }
        writeToFile("ERROR", msg);
    }

    private static void writeToFile(String level, String msg) {
        synchronized (LOCK) {
            if (logFile == null) return;
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(new Date());
            String line = ts + " [" + level + "] " + msg + "\n";
            try (FileWriter fw = new FileWriter(logFile, true)) {
                fw.write(line);
                fw.flush();
            } catch (IOException e) {
                Log.e(TAG, "Log write failed: " + e.getMessage());
            }
        }
    }
}
