package io.nekohasekai.sagernet.bg

import android.content.Context
import android.os.Process
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.Logs
import java.io.File

object TproxyHelper {
    private const val BIN = "libhev-socks5-tproxy.so"

    fun start(context: Context) {
        if (!RootShell.available()) {
            throw IllegalStateException("root (su) required for TPROXY")
        }
        val socks = DataStore.socksPort.takeIf { it in 1..65535 } ?: 2080
        val bin = File(context.applicationInfo.nativeLibraryDir, BIN)
        if (!bin.isFile) {
            throw IllegalStateException("$BIN missing — reinstall the APK")
        }
        val work = File(context.filesDir, "tproxy").apply { mkdirs() }
        val exe = File(work, "hev-socks5-tproxy")
        bin.copyTo(exe, overwrite = true)
        RootShell.chmod(exe)
        val hevLog = File(work, "hev.log")
        val yaml = File(work, "hev.yaml")
        yaml.writeText(
            """
            main:
              workers: 4
            socks5:
              port: $socks
              address: 127.0.0.1
              udp: 'udp'
              mark: ${TproxyRules.MARK_INT}
            tcp:
              port: ${TproxyRules.PORT}
              address: '0.0.0.0'
            udp:
              port: ${TproxyRules.PORT}
              address: '0.0.0.0'
            """.trimIndent(),
        )
        RootShell.exec(TproxyRules.cleanup())
        // Magisk su drops bare "&" children — setsid + nohup, then verify process
        val startCmd =
            "setsid nohup ${exe.absolutePath} ${yaml.absolutePath} " +
                ">${hevLog.absolutePath} 2>&1 </dev/null & echo \$!"
        val (startCode, startOut) = RootShell.execOut(startCmd)
        val pid = startOut.trim().lines().lastOrNull()?.trim().orEmpty()
        if (startCode != 0 && pid.isEmpty()) {
            throw IllegalStateException("hev spawn failed: ${startOut.take(400)}")
        }
        var alive = false
        repeat(25) {
            Thread.sleep(120)
            val (_, pg) = RootShell.execOut("pgrep -f hev-socks5-tproxy | head -1")
            if (pg.trim().isNotEmpty()) {
                alive = true
                return@repeat
            }
            if (pid.isNotEmpty()) {
                val (c, _) = RootShell.execOut("kill -0 $pid 2>/dev/null")
                if (c == 0) {
                    alive = true
                    return@repeat
                }
            }
        }
        if (!alive) {
            val log = runCatching { hevLog.readText().take(800) }.getOrDefault("")
            RootShell.exec(TproxyRules.cleanup())
            throw IllegalStateException("hev died before rules. log: $log")
        }
        val ipt = RootShell.exec(TproxyRules.setup(Process.myUid()))
        if (ipt != 0) {
            RootShell.exec(TproxyRules.cleanup())
            throw IllegalStateException("iptables TPROXY setup failed")
        }
        Logs.w("TPROXY up socks=$socks hev=:${TproxyRules.PORT} uid=${Process.myUid()} pid=$pid")
    }

    fun stop() {
        try {
            RootShell.exec(TproxyRules.cleanup())
        } catch (e: Exception) {
            Logs.w(e)
        }
    }
}
