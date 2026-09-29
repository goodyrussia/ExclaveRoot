package io.nekohasekai.sagernet.bg

/** Root TPROXY capture for Exclave Root. */
object TproxyRules {
    const val PORT = 12346
    const val MARK = "0x2741"
    const val MARK_INT = 0x2741
    const val TABLE = "2741"
    const val CHAIN_PRE = "EXCLAVE_ROOT_PRE"
    const val CHAIN_OUT = "EXCLAVE_ROOT_OUT"
    const val CHAIN_DIVERT = "EXCLAVE_ROOT_DIVERT"

    fun setup(uid: Int): String = """
        set -e
        IPT=iptables
        IP6=ip6tables
        uid=$uid
        port=$PORT
        mark=$MARK
        table=$TABLE
        pre=$CHAIN_PRE
        out=$CHAIN_OUT
        divert=$CHAIN_DIVERT

        ip rule del fwmark ${'$'}mark table ${'$'}table 2>/dev/null || true
        ip rule add fwmark ${'$'}mark lookup ${'$'}table pref 100
        ip route replace local 0.0.0.0/0 dev lo table ${'$'}table

        ${'$'}IPT -t mangle -N ${'$'}divert 2>/dev/null || ${'$'}IPT -t mangle -F ${'$'}divert
        ${'$'}IPT -t mangle -N ${'$'}pre 2>/dev/null || ${'$'}IPT -t mangle -F ${'$'}pre
        ${'$'}IPT -t mangle -N ${'$'}out 2>/dev/null || ${'$'}IPT -t mangle -F ${'$'}out

        ${'$'}IPT -t mangle -A ${'$'}divert -j MARK --set-xmark ${'$'}mark
        ${'$'}IPT -t mangle -A ${'$'}divert -j ACCEPT
        ${'$'}IPT -t mangle -A ${'$'}pre -p tcp -m socket -j ${'$'}divert 2>/dev/null || true
        ${'$'}IPT -t mangle -A ${'$'}pre -p tcp -j TPROXY --on-port ${'$'}port --tproxy-mark ${'$'}mark
        ${'$'}IPT -t mangle -A ${'$'}pre -p udp -j TPROXY --on-port ${'$'}port --tproxy-mark ${'$'}mark

        # core (app uid) + hev (root) must escape
        ${'$'}IPT -t mangle -A ${'$'}out -m owner --uid-owner ${'$'}uid -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -m owner --uid-owner 0 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 127.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 10.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 172.16.0.0/12 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 192.168.0.0/16 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -p tcp -j MARK --set-xmark ${'$'}mark
        ${'$'}IPT -t mangle -A ${'$'}out -p udp -j MARK --set-xmark ${'$'}mark

        ${'$'}IPT -t mangle -D PREROUTING -j ${'$'}pre 2>/dev/null || true
        ${'$'}IPT -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null || true
        ${'$'}IPT -t mangle -I PREROUTING 1 -j ${'$'}pre
        ${'$'}IPT -t mangle -I OUTPUT 1 -j ${'$'}out

        # IPv6 TPROXY if kernel allows — never blanket-REJECT (that blackholed dual-stack)
        ip -6 rule del fwmark ${'$'}mark table ${'$'}table 2>/dev/null || true
        ip -6 rule add fwmark ${'$'}mark lookup ${'$'}table pref 100 2>/dev/null || true
        ip -6 route replace local ::/0 dev lo table ${'$'}table 2>/dev/null || true
        ${'$'}IP6 -t mangle -N ${'$'}pre 2>/dev/null || ${'$'}IP6 -t mangle -F ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -N ${'$'}out 2>/dev/null || ${'$'}IP6 -t mangle -F ${'$'}out 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}pre -p tcp -j TPROXY --on-port ${'$'}port --tproxy-mark ${'$'}mark 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}pre -p udp -j TPROXY --on-port ${'$'}port --tproxy-mark ${'$'}mark 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -m owner --uid-owner ${'$'}uid -j RETURN 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -m owner --uid-owner 0 -j RETURN 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -d ::1/128 -j RETURN 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -p tcp -j MARK --set-xmark ${'$'}mark 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -p udp -j MARK --set-xmark ${'$'}mark 2>/dev/null || true
        ${'$'}IP6 -t mangle -D PREROUTING -j ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null || true
        ${'$'}IP6 -t mangle -I PREROUTING 1 -j ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -I OUTPUT 1 -j ${'$'}out 2>/dev/null || true
    """.trimIndent()

    fun cleanup(): String = """
        IPT=iptables
        IP6=ip6tables
        mark=$MARK
        table=$TABLE
        pre=$CHAIN_PRE
        out=$CHAIN_OUT
        divert=$CHAIN_DIVERT
        ${'$'}IPT -t mangle -D PREROUTING -j ${'$'}pre 2>/dev/null || true
        ${'$'}IPT -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null || true
        ${'$'}IPT -t mangle -F ${'$'}pre 2>/dev/null || true
        ${'$'}IPT -t mangle -F ${'$'}out 2>/dev/null || true
        ${'$'}IPT -t mangle -F ${'$'}divert 2>/dev/null || true
        ${'$'}IPT -t mangle -X ${'$'}pre 2>/dev/null || true
        ${'$'}IPT -t mangle -X ${'$'}out 2>/dev/null || true
        ${'$'}IPT -t mangle -X ${'$'}divert 2>/dev/null || true
        ${'$'}IP6 -t mangle -D PREROUTING -j ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null || true
        ${'$'}IP6 -t mangle -F ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -F ${'$'}out 2>/dev/null || true
        ${'$'}IP6 -t mangle -X ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -X ${'$'}out 2>/dev/null || true
        ${'$'}IP6 -t filter -D OUTPUT -j REJECT 2>/dev/null || true
        ip rule del fwmark ${'$'}mark table ${'$'}table 2>/dev/null || true
        ip -6 rule del fwmark ${'$'}mark table ${'$'}table 2>/dev/null || true
        ip route flush table ${'$'}table 2>/dev/null || true
        ip -6 route flush table ${'$'}table 2>/dev/null || true
        pkill -f hev-socks5-tproxy 2>/dev/null || true
        killall hev-socks5-tproxy 2>/dev/null || true
    """.trimIndent()
}
