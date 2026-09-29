package io.nekohasekai.sagernet.bg

import android.content.Context
import android.os.Process
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.Logs

/** AsteriskNG-style: core owns dokodemo port; install iptables after core is up. */
object TproxyHelper {
    fun start(context: Context) {
        if (!RootShell.available()) {
            throw IllegalStateException("root (su) required for TPROXY")
        }
        val port = DataStore.transproxyPort.takeIf { it in 1..65535 } ?: TproxyRules.PORT
        RootShell.exec(TproxyRules.cleanup())

        var ready = false
        repeat(50) {
            Thread.sleep(100)
            val hex = "%04X".format(port)
            val (_, out) = RootShell.execOut(
                "(ss -lntu 2>/dev/null || netstat -lntu 2>/dev/null) | grep -E '[:.]$port([[:space:]]|$)' | head -3",
            )
            if (out.contains(":$port") || out.contains(".$port")) {
                ready = true
                return@repeat
            }
            val (_, proc) = RootShell.execOut(
                "grep -E ':$hex ' /proc/net/tcp /proc/net/tcp6 2>/dev/null | head -1",
            )
            if (proc.isNotBlank()) {
                ready = true
                return@repeat
            }
        }
        if (!ready) {
            Logs.w("dokodemo :$port not observed yet; installing rules anyway")
        }
        val code = RootShell.exec(TproxyRules.setup(Process.myUid(), port))
        if (code != 0) {
            RootShell.exec(TproxyRules.cleanup())
            throw IllegalStateException("iptables setup failed (su exit $code)")
        }
        Logs.w("AsteriskNG-style TPROXY up port=$port uid=${Process.myUid()}")
    }

    fun stop() {
        try {
            RootShell.exec(TproxyRules.cleanup())
        } catch (e: Exception) {
            Logs.w(e)
        }
    }
}
