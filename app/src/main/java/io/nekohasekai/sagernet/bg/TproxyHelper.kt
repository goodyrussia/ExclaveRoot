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
        val yaml = File(work, "hev.yaml")
        yaml.writeText(
            """
            main:
              workers: 1
            socks5:
              port: $socks
              address: 127.0.0.1
              udp: 'udp'
            tcp:
              port: ${TproxyRules.PORT}
              address: '0.0.0.0'
            udp:
              port: ${TproxyRules.PORT}
              address: '0.0.0.0'
            """.trimIndent(),
        )
        RootShell.exec(TproxyRules.cleanup())
        val startHev = "nohup ${exe.absolutePath} ${yaml.absolutePath} >/dev/null 2>&1 &"
        val hevCode = RootShell.exec(startHev)
        if (hevCode != 0) {
            Logs.w("hev start code $hevCode")
        }
        val ipt = RootShell.exec(TproxyRules.setup(Process.myUid()))
        if (ipt != 0) {
            RootShell.exec(TproxyRules.cleanup())
            throw IllegalStateException("iptables TPROXY setup failed (need Magisk/KSU root)")
        }
    }

    fun stop() {
        try {
            RootShell.exec(TproxyRules.cleanup())
        } catch (e: Exception) {
            Logs.w(e)
        }
    }
}
