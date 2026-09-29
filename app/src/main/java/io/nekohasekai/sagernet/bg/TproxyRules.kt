package io.nekohasekai.sagernet.bg

/**
 * Root capture for in-process Exclave core (app uid).
 *
 * AsteriskNG uses real TPROXY because its core runs as root (setuidgid) with IP_TRANSPARENT.
 * Exclave Root's core is in-process under the app uid → TPROXY/mark blackholes traffic.
 * Working path: iptables nat OUTPUT REDIRECT → dokodemo followRedirect (SO_ORIGINAL_DST).
 * IPv6 is kill-switched so apps fall back to IPv4 REDIRECT.
 */
object TproxyRules {
    const val PORT = 12346
    const val MARK = "0x2741"
    const val MARK_INT = 0x2741
    const val TABLE = "2741"
    const val CHAIN_PRE = "EXCLAVE_ROOT_PRE"
    const val CHAIN_OUT = "EXCLAVE_ROOT_OUT"
    const val CHAIN_NAT = "EXCLAVE_ROOT_NAT"

    fun setup(uid: Int, port: Int = PORT): String = """

        set -e
        IPT=iptables
        IP6=ip6tables
        uid=$uid
        port=$port
        pre=$CHAIN_PRE
        out=$CHAIN_OUT
        nat=$CHAIN_NAT
        block6=EXCLAVE_ROOT_V6BLOCK

        # Clean any leftover mark/route from older builds
        while ip rule del fwmark 0x2741 table 2741 2>/dev/null; do :; done
        while ip -6 rule del fwmark 0x2741 table 2741 2>/dev/null; do :; done
        ip route flush table 2741 2>/dev/null || true
        ip -6 route flush table 2741 2>/dev/null || true

        ${'$'}IPT -t mangle -N ${'$'}out 2>/dev/null || ${'$'}IPT -t mangle -F ${'$'}out
        ${'$'}IPT -t nat -N ${'$'}nat 2>/dev/null || ${'$'}IPT -t nat -F ${'$'}nat

        # mangle OUTPUT: only used as a no-op holder / future hooks — escape only
        ${'$'}IPT -t mangle -A ${'$'}out -m owner --uid-owner ${'$'}uid -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -m owner --uid-owner 0 -j RETURN

        # nat OUTPUT REDIRECT → in-core dokodemo (followRedirect / SO_ORIGINAL_DST)
        ${'$'}IPT -t nat -A ${'$'}nat -m owner --uid-owner ${'$'}uid -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -m owner --uid-owner 0 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 0.0.0.0/8 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 10.0.0.0/8 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 100.0.0.0/8 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 127.0.0.0/8 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 169.254.0.0/16 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 172.16.0.0/12 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 192.0.0.0/24 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 192.0.2.0/24 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 192.88.99.0/24 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 192.168.0.0/16 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 198.18.0.0/15 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 198.51.100.0/24 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 203.0.113.0/24 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 224.0.0.0/4 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 240.0.0.0/4 -j RETURN
        ${'$'}IPT -t nat -A ${'$'}nat -d 255.255.255.255/32 -j RETURN
        # TCP all → dokodemo
        ${'$'}IPT -t nat -A ${'$'}nat -p tcp -j REDIRECT --to-ports ${'$'}port
        # DNS UDP → dokodemo (Android DNS)
        ${'$'}IPT -t nat -A ${'$'}nat -p udp -m udp --dport 53 -j REDIRECT --to-ports ${'$'}port

        while ${'$'}IPT -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null; do :; done
        while ${'$'}IPT -t nat -D OUTPUT -j ${'$'}nat 2>/dev/null; do :; done
        while ${'$'}IPT -t mangle -D PREROUTING -j EXCLAVE_ROOT_PRE 2>/dev/null; do :; done
        ${'$'}IPT -t mangle -F EXCLAVE_ROOT_PRE 2>/dev/null || true
        ${'$'}IPT -t mangle -X EXCLAVE_ROOT_PRE 2>/dev/null || true
        ${'$'}IPT -t mangle -I OUTPUT 1 -j ${'$'}out
        ${'$'}IPT -t nat -I OUTPUT 1 -j ${'$'}nat

        # IPv6 kill-switch: force apps onto IPv4 REDIRECT path (core is not root TPROXY)
        ${'$'}IP6 -t filter -N ${'$'}block6 2>/dev/null || ${'$'}IP6 -t filter -F ${'$'}block6
        ${'$'}IP6 -t filter -A ${'$'}block6 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || ${'$'}IP6 -t filter -A ${'$'}block6 -j REJECT
        while ${'$'}IP6 -t filter -D OUTPUT -j ${'$'}block6 2>/dev/null; do :; done
        while ${'$'}IP6 -t filter -D FORWARD -j ${'$'}block6 2>/dev/null; do :; done
        ${'$'}IP6 -t filter -I OUTPUT 1 -j ${'$'}block6
        ${'$'}IP6 -t filter -I FORWARD 1 -j ${'$'}block6 2>/dev/null || true
        # strip old v6 mangle hooks
        while ${'$'}IP6 -t mangle -D PREROUTING -j EXCLAVE_ROOT_PRE 2>/dev/null; do :; done
        while ${'$'}IP6 -t mangle -D OUTPUT -j EXCLAVE_ROOT_OUT 2>/dev/null; do :; done
        ${'$'}IP6 -t mangle -F EXCLAVE_ROOT_PRE 2>/dev/null || true
        ${'$'}IP6 -t mangle -F EXCLAVE_ROOT_OUT 2>/dev/null || true
        ${'$'}IP6 -t mangle -X EXCLAVE_ROOT_PRE 2>/dev/null || true
        ${'$'}IP6 -t mangle -X EXCLAVE_ROOT_OUT 2>/dev/null || true

    """.trimIndent()

    fun cleanup(): String = """

        IPT=iptables
        IP6=ip6tables
        out=$CHAIN_OUT
        nat=$CHAIN_NAT
        block6=EXCLAVE_ROOT_V6BLOCK
        while ${'$'}IPT -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null; do :; done
        while ${'$'}IPT -t nat -D OUTPUT -j ${'$'}nat 2>/dev/null; do :; done
        while ${'$'}IPT -t mangle -D PREROUTING -j EXCLAVE_ROOT_PRE 2>/dev/null; do :; done
        ${'$'}IPT -t mangle -F ${'$'}out 2>/dev/null || true
        ${'$'}IPT -t nat -F ${'$'}nat 2>/dev/null || true
        ${'$'}IPT -t mangle -F EXCLAVE_ROOT_PRE 2>/dev/null || true
        ${'$'}IPT -t mangle -X ${'$'}out 2>/dev/null || true
        ${'$'}IPT -t nat -X ${'$'}nat 2>/dev/null || true
        ${'$'}IPT -t mangle -X EXCLAVE_ROOT_PRE 2>/dev/null || true
        while ${'$'}IP6 -t filter -D OUTPUT -j ${'$'}block6 2>/dev/null; do :; done
        while ${'$'}IP6 -t filter -D FORWARD -j ${'$'}block6 2>/dev/null; do :; done
        ${'$'}IP6 -t filter -F ${'$'}block6 2>/dev/null || true
        ${'$'}IP6 -t filter -X ${'$'}block6 2>/dev/null || true
        while ${'$'}IP6 -t mangle -D PREROUTING -j EXCLAVE_ROOT_PRE 2>/dev/null; do :; done
        while ${'$'}IP6 -t mangle -D OUTPUT -j EXCLAVE_ROOT_OUT 2>/dev/null; do :; done
        ${'$'}IP6 -t mangle -F EXCLAVE_ROOT_PRE 2>/dev/null || true
        ${'$'}IP6 -t mangle -F EXCLAVE_ROOT_OUT 2>/dev/null || true
        ${'$'}IP6 -t mangle -X EXCLAVE_ROOT_PRE 2>/dev/null || true
        ${'$'}IP6 -t mangle -X EXCLAVE_ROOT_OUT 2>/dev/null || true
        while ip rule del fwmark 0x2741 table 2741 2>/dev/null; do :; done
        while ip -6 rule del fwmark 0x2741 table 2741 2>/dev/null; do :; done
        ip route flush table 2741 2>/dev/null || true
        ip -6 route flush table 2741 2>/dev/null || true
        pkill -f hev-socks5-tproxy 2>/dev/null || true

    """.trimIndent()
}
