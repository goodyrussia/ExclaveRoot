package io.nekohasekai.sagernet.bg

import io.nekohasekai.sagernet.ktx.Logs
import java.io.File

object RootShell {
    fun exec(script: String): Int {
        val process = ProcessBuilder("su", "-c", script)
            .redirectErrorStream(true)
            .start()
        val out = process.inputStream.bufferedReader().readText()
        val code = process.waitFor()
        if (code != 0) {
            Logs.w("su($code): ${out.take(2000)}")
        }
        return code
    }

    fun available(): Boolean {
        return try {
            exec("id") == 0
        } catch (e: Exception) {
            Logs.w(e)
            false
        }
    }

    fun chmod(path: File, mode: String = "755") {
        path.setReadable(true, false)
        path.setExecutable(true, false)
        exec("chmod $mode ${path.absolutePath}")
    }
}
