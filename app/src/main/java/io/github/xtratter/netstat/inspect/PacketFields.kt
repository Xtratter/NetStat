package io.github.xtratter.netstat.inspect

import java.net.Inet6Address

internal data class PacketField(val name: String, val value: String, val start: Int, val end: Int)
internal data class PacketLayer(val name: String, val fields: List<PacketField>)

internal fun packetLayers(bytes: ByteArray): List<PacketLayer> = buildList {
    val version = bytes.firstOrNull()?.let { (it.toInt() and 0xFF) ushr 4 }
    when (version) {
        4 -> ipv4Layers(bytes, this)
        6 -> ipv6Layers(bytes, this)
        else -> add(PacketLayer("Unknown packet", buildList {
            if (version == null) add(PacketField("Status", "Empty packet", 0, 0))
            else {
                add(PacketField("IP version", version.toString(), 0, 1))
                add(PacketField("Data", "${bytes.size} bytes", 0, bytes.size))
            }
        }))
    }
}

private fun ipv4Layers(bytes: ByteArray, layers: MutableList<PacketLayer>) {
    val headerBytes = (bytes.u8(0) and 0xF) * 4
    val ip = Fields(bytes, bytes.size)
    ip.add("Version", "4", 0, 1)
    ip.add("Header length", "$headerBytes bytes", 0, 1)
    ip.number("DSCP", 1, 1) { (it.toInt() ushr 2).toString() }
    ip.number("ECN", 1, 1) { (it.toInt() and 3).toString() }
    ip.number("Total length", 2, 2)
    ip.number("Identification", 4, 2, ::hexWord)
    ip.number("Flags", 6, 2) { bits(it.toInt() ushr 13, listOf("MF", "DF", "Reserved")) }
    ip.number("Fragment offset", 6, 2) { "${(it.toInt() and 0x1FFF) * 8} bytes" }
    ip.number("TTL", 8, 1)
    ip.number("Protocol", 9, 1) { protocolName(it.toInt()) }
    ip.number("Header checksum", 10, 2, ::hexWord)
    ip.address("Source", 12, 4)
    ip.address("Destination", 16, 4)

    val malformed = when {
        headerBytes < 20 -> "Invalid IPv4 header length"
        bytes.size < headerBytes -> "Truncated IPv4 header"
        bytes.u16(2) < headerBytes -> "IPv4 total length is shorter than its header"
        else -> null
    }
    if (malformed != null) {
        ip.status(malformed, 0, minOf(bytes.size, maxOf(20, headerBytes)))
        layers.add(ip.layer("IPv4"))
        return
    }

    ip.data("Options", 20, headerBytes)
    val end = minOf(bytes.size, bytes.u16(2))
    if (bytes.u16(2) > bytes.size) ip.status("Truncated IPv4 packet", 2, 4)
    layers.add(ip.layer("IPv4"))
    val fragment = bytes.u16(6)
    if (fragment and 0x1FFF != 0) {
        layers.add(dataLayer(bytes, "Fragment payload", headerBytes, end))
        return
    }
    transportLayers(bytes, bytes.u8(9), headerBytes, end, fragment and 0x2000 != 0, layers)
}

private fun ipv6Layers(bytes: ByteArray, layers: MutableList<PacketLayer>) {
    val ipv6 = Fields(bytes, bytes.size)
    ipv6.add("Version", "6", 0, 1)
    ipv6.number("Traffic class", 0, 2) { ((it.toInt() ushr 4) and 0xFF).toString() }
    ipv6.number("Flow label", 1, 3) { "0x${(it.toInt() and 0xFFFFF).toString(16).padStart(5, '0')}" }
    ipv6.number("Payload length", 4, 2)
    ipv6.number("Next header", 6, 1) { protocolName(it.toInt()) }
    ipv6.number("Hop limit", 7, 1)
    ipv6.address("Source", 8, 16)
    ipv6.address("Destination", 24, 16)
    if (bytes.size < 40) {
        ipv6.status("Truncated IPv6 header", 0, bytes.size)
        layers.add(ipv6.layer("IPv6"))
        return
    }

    val declaredEnd = 40 + bytes.u16(4)
    val end = minOf(declaredEnd, bytes.size)
    if (declaredEnd > bytes.size) ipv6.status("Truncated IPv6 packet", 4, 6)
    if (declaredEnd == 40 && bytes.size > 40) ipv6.status("Trailing bytes outside the IPv6 payload", 4, 6)
    layers.add(ipv6.layer("IPv6"))
    ipv6Payload(bytes, bytes.u8(6), end, layers)
}

private fun ipv6Payload(bytes: ByteArray, initialProtocol: Int, end: Int, layers: MutableList<PacketLayer>) {
    var protocol = initialProtocol
    var offset = 40
    var moreFragments = false
    var extensions = 0

    while (protocol in EXTENSION_HEADERS) {
        if (extensions++ >= 8) {
            val fields = Fields(bytes, end)
            fields.status("IPv6 extension header limit reached", offset)
            fields.data("Data", offset, end)
            layers.add(fields.layer("IPv6 extensions"))
            return
        }

        val name = protocolName(protocol).substringBefore(" (")
        val fields = Fields(bytes, end)
        fields.number("Next header", offset, 1) { protocolName(it.toInt()) }
        if (protocol != 44) fields.number("Header length", offset + 1, 1) {
            "${extensionSize(protocol, it.toInt())} bytes"
        }
        val size = when {
            protocol == 44 -> 8
            offset + 2 <= end -> extensionSize(protocol, bytes.u8(offset + 1))
            else -> 0
        }
        if (size == 0 || offset + size > end || (protocol == 51 && size < 12)) {
            fields.status("Truncated or invalid IPv6 extension", offset, end)
            layers.add(fields.layer(name))
            return
        }
        if (protocol == 44) {
            val fragment = bytes.u16(offset + 2)
            fields.number("Fragment offset", offset + 2, 2) { "${it.toInt() and 0xFFF8} bytes" }
            fields.number("More fragments", offset + 2, 2) { if (it.toInt() and 1 != 0) "Yes" else "No" }
            fields.number("Identification", offset + 4, 4) { "0x${it.toString(16).padStart(8, '0')}" }
            moreFragments = fragment and 1 != 0
            layers.add(fields.layer(name))
            if (fragment and 0xFFF8 != 0) {
                layers.add(dataLayer(bytes, "Fragment payload", offset + size, end))
                return
            }
        } else {
            if (protocol == 43) {
                fields.number("Routing type", offset + 2, 1)
                fields.number("Segments left", offset + 3, 1)
                fields.data("Data", offset + 4, offset + size)
            } else if (protocol == 51) {
                fields.number("Security parameters index", offset + 4, 4)
                fields.number("Sequence number", offset + 8, 4)
                fields.data("Authentication data", offset + 12, offset + size)
            } else {
                fields.data("Options", offset + 2, offset + size)
            }
            layers.add(fields.layer(name))
        }
        protocol = bytes.u8(offset)
        offset += size
    }
    transportLayers(bytes, protocol, offset, end, moreFragments, layers)
}

private val EXTENSION_HEADERS = setOf(0, 43, 44, 51, 60)

private fun extensionSize(protocol: Int, encoded: Int) =
    if (protocol == 51) (encoded + 2) * 4 else (encoded + 1) * 8

private fun transportLayers(
    bytes: ByteArray,
    protocol: Int,
    offset: Int,
    end: Int,
    moreFragments: Boolean,
    layers: MutableList<PacketLayer>,
) {
    when (protocol) {
        6 -> tcpLayers(bytes, offset, end, moreFragments, layers)
        17 -> udpLayers(bytes, offset, end, moreFragments, layers)
        59 -> if (offset < end) layers.add(dataLayer(bytes, "Opaque IPv6 payload", offset, end))
        else -> if (offset < end) layers.add(dataLayer(bytes, "Unknown IP payload", offset, end))
    }
}

private fun tcpLayers(bytes: ByteArray, start: Int, end: Int, more: Boolean, layers: MutableList<PacketLayer>) {
    val tcp = Fields(bytes, end)
    tcp.number("Source port", start, 2)
    tcp.number("Destination port", start + 2, 2)
    tcp.number("Sequence number", start + 4, 4)
    tcp.number("Acknowledgment number", start + 8, 4)
    tcp.number("Header length", start + 12, 1) { "${(it.toInt() ushr 4) * 4} bytes" }
    tcp.number("Flags", start + 12, 2) {
        bits(it.toInt(), listOf("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "AE"))
    }
    tcp.number("Window", start + 14, 2)
    tcp.number("Checksum", start + 16, 2, ::hexWord)
    tcp.number("Urgent pointer", start + 18, 2)

    if (start + 20 > end) {
        tcp.status("Truncated TCP header", start, end)
        layers.add(tcp.layer("TCP"))
        return
    }
    val headerLength = (bytes.u8(start + 12) ushr 4) * 4
    if (headerLength < 20 || start + headerLength > end) {
        tcp.status("Truncated or invalid TCP header length", start + 12, start + 13)
        layers.add(tcp.layer("TCP"))
        return
    }
    val payloadStart = start + headerLength
    tcp.data("Options", start + 20, payloadStart)
    tcp.data("Payload", payloadStart, end)
    layers.add(tcp.layer("TCP"))
    if (!more && usesDnsPort(bytes, start)) tcpDnsLayers(bytes, payloadStart, end, layers)
}

private fun udpLayers(bytes: ByteArray, start: Int, end: Int, more: Boolean, layers: MutableList<PacketLayer>) {
    val udp = Fields(bytes, end)
    udp.number("Source port", start, 2)
    udp.number("Destination port", start + 2, 2)
    udp.number("Length", start + 4, 2)
    udp.number("Checksum", start + 6, 2, ::hexWord)
    if (start + 8 > end) {
        udp.status("Truncated UDP header", start, end)
        layers.add(udp.layer("UDP"))
        return
    }
    val declared = bytes.u16(start + 4)
    if (declared < 8) {
        udp.status("Invalid UDP length", start + 4, start + 6)
        layers.add(udp.layer("UDP"))
        return
    }
    val last = minOf(end, start + declared)
    val payload = start + 8
    if (start + declared > end && !more) udp.status("Truncated UDP datagram", start + 4, start + 6)
    udp.data("Payload", payload, last)
    layers.add(udp.layer("UDP"))
    if (!more && payload < last && usesDnsPort(bytes, start)) {
        layers.add(dnsLayer(bytes, payload, last))
    }
}

private fun usesDnsPort(bytes: ByteArray, start: Int) = bytes.u16(start) == 53 || bytes.u16(start + 2) == 53

private fun tcpDnsLayers(bytes: ByteArray, start: Int, end: Int, layers: MutableList<PacketLayer>) {
    var position = start
    repeat(8) {
        if (position == end) return
        if (position + 2 > end) {
            val fields = Fields(bytes, end)
            fields.status("Truncated DNS over TCP length", position, end)
            layers.add(fields.layer("DNS"))
            return
        }
        val size = bytes.u16(position)
        val body = position + 2
        val last = minOf(end, body + size)
        layers.add(dnsLayer(bytes, body, last, position, body + size > end))
        if (body + size > end || size < 12) return
        position = last
    }
    if (position < end) {
        val fields = Fields(bytes, end)
        fields.status("DNS over TCP message limit reached", position)
        fields.data("Data", position, end)
        layers.add(fields.layer("DNS"))
    }
}

private fun dataLayer(bytes: ByteArray, name: String, start: Int, end: Int): PacketLayer =
    Fields(bytes, end).apply { data("Data", start, end) }.layer(name)

private fun dnsLayer(bytes: ByteArray, start: Int, end: Int, prefix: Int? = null, truncated: Boolean = false): PacketLayer {
    val dns = Fields(bytes, end)
    if (prefix != null) dns.number("TCP message length", prefix, 2)
    dns.number("Transaction ID", start, 2, ::hexWord)
    dns.number("Flags", start + 2, 2, ::hexWord)
    dns.number("Questions", start + 4, 2)
    dns.number("Answers", start + 6, 2)
    dns.number("Authority records", start + 8, 2)
    dns.number("Additional records", start + 10, 2)
    if (truncated) dns.status("Truncated DNS over TCP message", start, end)
    if (start + 12 > end) {
        dns.status("Truncated DNS header", start, end)
        return dns.layer("DNS")
    }

    val names = listOf("Question", "Answer", "Authority", "Additional")
    var position = start + 12
    var parsed = 0
    for ((section, name) in names.withIndex()) {
        val count = bytes.u16(start + 4 + section * 2)
        for (index in 1..count) {
            if (parsed++ >= 64) {
                dns.status("DNS record limit reached", position)
                return dns.layer("DNS")
            }
            position = dnsRecord(bytes, dns, start, end, position, "$name $index", section == 0)
                ?: return dns.layer("DNS")
        }
    }
    return dns.layer("DNS")
}

private fun dnsRecord(
    bytes: ByteArray,
    fields: Fields,
    messageStart: Int,
    messageEnd: Int,
    start: Int,
    label: String,
    question: Boolean,
): Int? {
    val domain = dnsName(bytes, messageStart, messageEnd, start, messageEnd)
    if (domain == null) {
        fields.status("Invalid or truncated DNS name", start)
        return null
    }
    fields.add("$label name", domain.text, start, domain.wireEnd)
    val offset = domain.wireEnd
    fields.number("$label type", offset, 2) { dnsType(it.toInt()) }
    fields.number("$label class", offset + 2, 2)
    val fixed = if (question) 4 else 10
    if (offset + fixed > messageEnd) {
        fields.status("Truncated DNS record", offset, messageEnd)
        return null
    }
    if (question) return offset + fixed

    fields.number("$label TTL", offset + 4, 4)
    fields.number("$label data length", offset + 8, 2)
    val data = offset + fixed
    val length = bytes.u16(offset + 8)
    if (data + length > messageEnd) {
        fields.status("Truncated DNS record data", data, messageEnd)
        return null
    }
    val last = data + length
    val type = bytes.u16(offset)
    fields.add("$label data", dnsData(bytes, type, messageStart, messageEnd, data, last), data, last)
    return last
}

private fun dnsData(bytes: ByteArray, type: Int, messageStart: Int, messageEnd: Int, start: Int, end: Int): String {
    fun name(at: Int): String = dnsName(bytes, messageStart, messageEnd, at, end)
        ?.takeIf { it.wireEnd == end }?.text ?: "Invalid DNS name"
    val length = end - start
    return when (type) {
        1 -> if (length == 4) addressText(bytes, start, 4) else "Invalid IPv4 address"
        28 -> if (length == 16) addressText(bytes, start, 16) else "Invalid IPv6 address"
        2, 5, 12, 39 -> name(start)
        15 -> if (length > 2) "${bytes.u16(start)} ${name(start + 2)}" else "Invalid MX record"
        33 -> if (length > 6) {
            "${bytes.u16(start)} ${bytes.u16(start + 2)} ${bytes.u16(start + 4)} ${name(start + 6)}"
        } else "Invalid SRV record"
        else -> "$length bytes"
    }
}

private data class DnsName(val text: String, val wireEnd: Int)

private fun dnsName(bytes: ByteArray, messageStart: Int, messageEnd: Int, start: Int, localEnd: Int): DnsName? {
    val labels = mutableListOf<String>()
    val visited = mutableSetOf<Int>()
    var cursor = start
    var wireEnd: Int? = null
    var expandedLength = 1
    repeat(128) {
        val limit = if (wireEnd == null) localEnd else messageEnd
        if (cursor < messageStart + 12 || cursor >= limit || !visited.add(cursor)) return null
        val length = bytes.u8(cursor)
        when {
            length == 0 -> return DnsName(labels.joinToString(".").ifEmpty { "." }, wireEnd ?: cursor + 1)
            length and 0xC0 == 0xC0 -> {
                if (cursor + 2 > limit) return null
                val target = messageStart + (bytes.u16(cursor) and 0x3FFF)
                if (target >= cursor) return null
                if (wireEnd == null) wireEnd = cursor + 2
                cursor = target
            }
            length > 63 || cursor + 1 + length > limit -> return null
            else -> {
                expandedLength += length + 1
                if (expandedLength > 255) return null
                labels.add(buildString {
                    for (index in cursor + 1..cursor + length) {
                        val value = bytes.u8(index)
                        if (value in 33..126 && value != 46 && value != 92) append(value.toChar())
                        else append("\\").append(value.toString().padStart(3, '0'))
                    }
                })
                cursor += 1 + length
            }
        }
    }
    return null
}

private class Fields(private val bytes: ByteArray, private val end: Int) {
    private val fields = mutableListOf<PacketField>()

    fun add(name: String, value: String, start: Int, end: Int) {
        fields.add(PacketField(name, value, start, end))
    }

    fun number(name: String, start: Int, length: Int, format: (Long) -> String = { it.toString() }) {
        if (start + length > end) return
        var value = 0L
        for (index in start until start + length) value = (value shl 8) or bytes.u8(index).toLong()
        add(name, format(value), start, start + length)
    }

    fun address(name: String, start: Int, length: Int) {
        if (start + length <= end) add(name, addressText(bytes, start, length), start, start + length)
    }

    fun data(name: String, start: Int, last: Int) {
        if (start < last && last <= end) add(name, "${last - start} bytes", start, last)
    }

    fun status(text: String, start: Int, last: Int = start) {
        add("Status", text, start.coerceAtMost(end), last.coerceAtMost(end))
    }

    fun layer(name: String) = PacketLayer(name, fields.toList())
}

private fun addressText(bytes: ByteArray, start: Int, length: Int): String = if (length == 4) {
    (start until start + 4).joinToString(".") { bytes.u8(it).toString() }
} else {
    Inet6Address.getByAddress(null, bytes.copyOfRange(start, start + 16), -1).hostAddress.orEmpty()
}

private fun ByteArray.u8(at: Int) = this[at].toInt() and 0xFF
private fun ByteArray.u16(at: Int) = (u8(at) shl 8) or u8(at + 1)

private fun hexWord(value: Long) = "0x${value.toString(16).padStart(4, '0')}"

private fun bits(value: Int, names: List<String>): String =
    names.filterIndexed { index, _ -> value and (1 shl index) != 0 }.joinToString(", ").ifEmpty { "None" }

private fun protocolName(value: Int): String = when (value) {
    0 -> "Hop-by-Hop options (0)"
    1 -> "ICMP (1)"
    6 -> "TCP (6)"
    17 -> "UDP (17)"
    43 -> "IPv6 routing (43)"
    44 -> "IPv6 fragment (44)"
    50 -> "ESP (50)"
    51 -> "Authentication header (51)"
    58 -> "ICMPv6 (58)"
    59 -> "No next header (59)"
    60 -> "Destination options (60)"
    else -> value.toString()
}

private fun dnsType(value: Int): String = when (value) {
    1 -> "A (1)"
    2 -> "NS (2)"
    5 -> "CNAME (5)"
    6 -> "SOA (6)"
    12 -> "PTR (12)"
    15 -> "MX (15)"
    16 -> "TXT (16)"
    28 -> "AAAA (28)"
    33 -> "SRV (33)"
    39 -> "DNAME (39)"
    41 -> "OPT (41)"
    65 -> "HTTPS (65)"
    else -> value.toString()
}
