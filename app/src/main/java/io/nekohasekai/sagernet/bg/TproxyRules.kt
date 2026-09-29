package io.nekohasekai.sagernet.bg

/** AsteriskNG-style root capture: mark→TPROXY + nat REDIRECT fallback → in-core dokodemo. */
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
        mark=$MARK
        table=$TABLE
        pre=$CHAIN_PRE
        out=$CHAIN_OUT
        nat=$CHAIN_NAT

        while ip rule del fwmark ${'$'}mark table ${'$'}table 2>/dev/null; do :; done
        ip rule add fwmark ${'$'}mark lookup ${'$'}table pref 100
        ip route replace local default dev lo table ${'$'}table

        ${'$'}IPT -t mangle -N ${'$'}pre 2>/dev/null || ${'$'}IPT -t mangle -F ${'$'}pre
        ${'$'}IPT -t mangle -N ${'$'}out 2>/dev/null || ${'$'}IPT -t mangle -F ${'$'}out
        ${'$'}IPT -t nat -N ${'$'}nat 2>/dev/null || ${'$'}IPT -t nat -F ${'$'}nat

        ${'$'}IPT -t mangle -A ${'$'}pre -d 0.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 10.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 100.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 127.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 169.254.0.0/16 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 172.16.0.0/12 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 192.0.0.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 192.0.2.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 192.88.99.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 192.168.0.0/16 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 198.18.0.0/15 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 198.51.100.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 203.0.113.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 224.0.0.0/4 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 240.0.0.0/4 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -d 255.255.255.255/32 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}pre -p tcp -m mark --mark ${'$'}mark -j TPROXY --on-port ${'$'}port --on-ip 0.0.0.0 --tproxy-mark ${'$'}mark
        ${'$'}IPT -t mangle -A ${'$'}pre -p udp -m mark --mark ${'$'}mark -j TPROXY --on-port ${'$'}port --on-ip 0.0.0.0 --tproxy-mark ${'$'}mark

        ${'$'}IPT -t mangle -A ${'$'}out -m owner --uid-owner ${'$'}uid -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -m owner --uid-owner 0 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 0.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 10.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 100.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 127.0.0.0/8 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 169.254.0.0/16 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 172.16.0.0/12 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 192.0.0.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 192.0.2.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 192.88.99.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 192.168.0.0/16 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 198.18.0.0/15 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 198.51.100.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 203.0.113.0/24 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 224.0.0.0/4 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 240.0.0.0/4 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -d 255.255.255.255/32 -j RETURN
        ${'$'}IPT -t mangle -A ${'$'}out -p udp -m udp --dport 53 -j MARK --set-xmark ${'$'}mark
        ${'$'}IPT -t mangle -A ${'$'}out -p tcp -j MARK --set-xmark ${'$'}mark
        ${'$'}IPT -t mangle -A ${'$'}out -p udp -j MARK --set-xmark ${'$'}mark

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
        ${'$'}IPT -t nat -A ${'$'}nat -p tcp -j REDIRECT --to-ports ${'$'}port
        ${'$'}IPT -t nat -A ${'$'}nat -p udp --dport 53 -j REDIRECT --to-ports ${'$'}port
        ${'$'}IPT -t nat -A ${'$'}nat -p udp -j REDIRECT --to-ports ${'$'}port

        while ${'$'}IPT -t mangle -D PREROUTING -j ${'$'}pre 2>/dev/null; do :; done
        while ${'$'}IPT -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null; do :; done
        while ${'$'}IPT -t nat -D OUTPUT -j ${'$'}nat 2>/dev/null; do :; done
        ${'$'}IPT -t mangle -I PREROUTING 1 -j ${'$'}pre
        ${'$'}IPT -t mangle -I OUTPUT 1 -j ${'$'}out
        ${'$'}IPT -t nat -I OUTPUT 1 -j ${'$'}nat

        while ip -6 rule del fwmark ${'$'}mark table ${'$'}table 2>/dev/null; do :; done
        ip -6 rule add fwmark ${'$'}mark lookup ${'$'}table pref 100 2>/dev/null || true
        ip -6 route replace local default dev lo table ${'$'}table 2>/dev/null || true
        ${'$'}IP6 -t mangle -N ${'$'}pre 2>/dev/null || ${'$'}IP6 -t mangle -F ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -N ${'$'}out 2>/dev/null || ${'$'}IP6 -t mangle -F ${'$'}out 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}pre -p tcp -m mark --mark ${'$'}mark -j TPROXY --on-port ${'$'}port --on-ip :: --tproxy-mark ${'$'}mark 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}pre -p udp -m mark --mark ${'$'}mark -j TPROXY --on-port ${'$'}port --on-ip :: --tproxy-mark ${'$'}mark 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -m owner --uid-owner ${'$'}uid -j RETURN 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -m owner --uid-owner 0 -j RETURN 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -d ::1/128 -j RETURN 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -p udp --dport 53 -j MARK --set-xmark ${'$'}mark 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -p tcp -j MARK --set-xmark ${'$'}mark 2>/dev/null || true
        ${'$'}IP6 -t mangle -A ${'$'}out -p udp -j MARK --set-xmark ${'$'}mark 2>/dev/null || true
        while ${'$'}IP6 -t mangle -D PREROUTING -j ${'$'}pre 2>/dev/null; do :; done
        while ${'$'}IP6 -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null; do :; done
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
        nat=$CHAIN_NAT
        while ${'$'}IPT -t mangle -D PREROUTING -j ${'$'}pre 2>/dev/null; do :; done
        while ${'$'}IPT -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null; do :; done
        while ${'$'}IPT -t nat -D OUTPUT -j ${'$'}nat 2>/dev/null; do :; done
        ${'$'}IPT -t mangle -F ${'$'}pre 2>/dev/null || true
        ${'$'}IPT -t mangle -F ${'$'}out 2>/dev/null || true
        ${'$'}IPT -t nat -F ${'$'}nat 2>/dev/null || true
        ${'$'}IPT -t mangle -X ${'$'}pre 2>/dev/null || true
        ${'$'}IPT -t mangle -X ${'$'}out 2>/dev/null || true
        ${'$'}IPT -t nat -X ${'$'}nat 2>/dev/null || true
        while ${'$'}IP6 -t mangle -D PREROUTING -j ${'$'}pre 2>/dev/null; do :; done
        while ${'$'}IP6 -t mangle -D OUTPUT -j ${'$'}out 2>/dev/null; do :; done
        ${'$'}IP6 -t mangle -F ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -F ${'$'}out 2>/dev/null || true
        ${'$'}IP6 -t mangle -X ${'$'}pre 2>/dev/null || true
        ${'$'}IP6 -t mangle -X ${'$'}out 2>/dev/null || true
        while ip rule del fwmark ${'$'}mark table ${'$'}table 2>/dev/null; do :; done
        while ip -6 rule del fwmark ${'$'}mark table ${'$'}table 2>/dev/null; do :; done
        ip route flush table ${'$'}table 2>/dev/null || true
        ip -6 route flush table ${'$'}table 2>/dev/null || true
        pkill -f hev-socks5-tproxy 2>/dev/null || true

    """.trimIndent()
}
