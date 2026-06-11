package org.usg.sipclient

import android.system.Os
import android.util.Log
import java.io.FileInputStream

/**
 * Pipes the process's stderr (fd 2) into logcat under the [TAG] tag.
 *
 * The Rust core logs through `tracing-subscriber` to **stderr** (see
 * `initLogging`). Android does not route a process's stderr to logcat by
 * default, so without this bridge the core's logs — including
 * "Application initialization complete" — are invisible to `adb logcat`.
 *
 * This duplicates the write end of a pipe onto fd 2 and drains the read end on a
 * daemon thread, emitting each line via [Log]. Best-effort: any failure leaves
 * stderr as-is.
 */
object LogcatBridge {
    private const val TAG = "UsgSipClientRust"
    private const val STDERR_FD = 2

    @Volatile private var installed = false

    fun install() {
        if (installed) return
        installed = true
        runCatching {
            // pipe[0] = read end, pipe[1] = write end.
            val pipe = Os.pipe()
            // Redirect fd 2 (stderr) to the pipe's write end.
            Os.dup2(pipe[1], STDERR_FD)
            val reader = FileInputStream(pipe[0]).bufferedReader()
            Thread {
                reader.forEachLine { line -> Log.i(TAG, line) }
            }.apply {
                isDaemon = true
                name = "stderr->logcat"
            }.start()
        }
    }
}
