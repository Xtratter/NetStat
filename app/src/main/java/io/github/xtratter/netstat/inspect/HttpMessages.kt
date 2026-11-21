package io.github.xtratter.netstat.inspect

import io.github.xtratter.netstat.capture.Endpoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.zip.GZIPInputStream

private const val HEADER_LIMIT = 32 * 1024
private const val BODY_LIMIT = 256 * 1024
private val token = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
private val requestLine = Regex("([^ ]+) ([^ \\p{Cntrl}]+) HTTP/1\\.[01]")
private val statusLine = Regex("HTTP/1\\.[01] ([1-5][0-9]{2})(?: (.*))?")
private val charsetParameter = Regex("""(?:^|;)\s*charset\s*=\s*"?([^;"\s]+)""", RegexOption.IGNORE_CASE)

internal data class HttpHeader(val name: String, val value: String)

internal data class HttpMessage(
    val line: String,
    val headers: List<HttpHeader>,
    val body: ByteArray,
    val bodySize: Int,
    val text: String?,
    val contentType: String?,
    val partial: Boolean,
    val previewLimited: Boolean,
    val encodingUnavailable: Boolean,
    val method: String? = null,
    val path: String? = null,
    val target: String? = null,
    val status: Int? = null,
) {
    fun matches(query: String): Boolean =
        line.contains(query, ignoreCase = true) || target?.contains(query, ignoreCase = true) == true ||
            headers.any { "${it.name}: ${it.value}".contains(query, ignoreCase = true) } ||
            text?.contains(query, ignoreCase = true) == true
}

internal data class HttpExchange(
    val client: Endpoint,
    val server: Endpoint,
    val request: HttpMessage?,
    val responses: List<HttpMessage>,
    val incomplete: Boolean,
) {
    fun matches(query: String) = request?.matches(query) == true || responses.any { it.matches(query) }
}

internal class HttpBudget {
    private var bytesLeft = 4 * 1024 * 1024
    private var messagesLeft = 1024
    var limited = false
        private set
    val full: Boolean get() = messagesLeft == 0 || bytesLeft == 0

    fun takeHeaders(size: Int): Boolean {
        if (full || size > bytesLeft) {
            limited = true
            return false
        }
        messagesLeft--
        bytesLeft -= size
        return true
    }

    fun bodyLimit(): Int = minOf(BODY_LIMIT, bytesLeft)

    fun takeBody(size: Int) {
        bytesLeft -= size
    }
}

internal fun isHttpRequest(bytes: ByteArray): Boolean = firstLine(bytes).let {
    val method = it?.let(requestLine::matchEntire)?.groupValues?.get(1)
    method != null && token.matches(method)
}

internal fun isHttpResponse(bytes: ByteArray) = firstLine(bytes)?.let(statusLine::matches) == true

private fun firstLine(bytes: ByteArray): String? {
    val newline = lineEnd(bytes, 0, minOf(HEADER_LIMIT, bytes.size))
    if (newline >= 0) return ascii(bytes, 0, newline)
    return if (bytes.size <= HEADER_LIMIT) ascii(bytes, 0, bytes.size).removeSuffix("\r") else null
}

internal fun parseHttp(
    client: Endpoint, server: Endpoint, requests: TcpStream, responses: TcpStream, budget: HttpBudget,
    uncertainStart: Boolean = false,
): List<HttpExchange> {
    val outgoing = HttpReader(requests, budget)
    val incoming = HttpReader(responses, budget)
    val result = mutableListOf<HttpExchange>()
    var upgrade = false
    var repliesAvailable = true
    while (!budget.full) {
        val request = outgoing.read(response = false) ?: break
        val replies = buildList {
            while (repliesAvailable && !budget.full) {
                val response = incoming.read(response = true, request.method) ?: break
                add(response)
                val status = checkNotNull(response.status)
                upgrade = status == 101 || (request.method == "CONNECT" && status in 200..299)
                if (upgrade || status >= 200 || response.partial) break
            }
        }
        val last = replies.lastOrNull()
        val hasFinal = upgrade || (last?.status ?: 0) >= 200
        result.add(HttpExchange(client, server, request, replies,
            uncertainStart || request.partial || !hasFinal || replies.any { it.partial }))
        if (!hasFinal || last?.partial == true) repliesAvailable = false
        if (upgrade || request.partial) break
    }
    if (!upgrade && result.none { it.request != null }) {
        // A capture can begin after the request. Its response is useful, but the exchange is incomplete.
        val response = incoming.read(response = true)
        if (response != null) result.add(HttpExchange(client, server, null, listOf(response), true))
    }
    if (budget.full && (outgoing.hasBytes || incoming.hasBytes)) budget.takeHeaders(0)
    if (!upgrade && result.isNotEmpty() && (requests.damaged || responses.damaged ||
            outgoing.hasBytes || incoming.hasBytes)) {
        val last = result.lastIndex
        result[last] = result[last].copy(incomplete = true)
    }
    return result
}

private class HttpReader(private val stream: TcpStream, private val budget: HttpBudget) {
    private val bytes = stream.bytes
    private var pos = 0
    private var stopped = false
    val hasBytes: Boolean get() = pos < bytes.size

    fun read(response: Boolean, method: String? = null): HttpMessage? {
        if (stopped || !hasBytes) return null
        val start = pos
        val limit = minOf(bytes.size, start + HEADER_LIMIT)
        val lineEnd = lineEnd(bytes, pos, limit)
        val line = if (lineEnd < 0) ascii(bytes, pos, limit).removeSuffix("\r") else ascii(bytes, pos, lineEnd)
        val status = if (response) statusLine.matchEntire(line)?.groupValues?.get(1)?.toInt() ?: return null else null
        val request = if (!response) requestLine.matchEntire(line) ?: return null else null
        val verb = request?.groupValues?.get(1)
        if (verb != null && !token.matches(verb)) return null
        val path = request?.groupValues?.get(2)
        val headers = mutableListOf<HttpHeader>()
        var complete = false
        pos = if (lineEnd < 0) limit else lineEnd + 2
        if (lineEnd >= 0) complete = readHeaders(headers, limit)
        if (!budget.takeHeaders(pos - start)) return null

        val target = when {
            path == null -> null
            path.startsWith("/") -> headers.firstValue("Host")?.let { "http://$it$path" } ?: path
            else -> path
        }
        val media = headers.firstValue("Content-Type")
        val bodyless = status != null && (method == "HEAD" || status < 200 || status == 204 ||
            status == 304 || (method == "CONNECT" && status in 200..299))
        val transfer = headers.codings("Transfer-Encoding")
        val chunked = transfer.lastOrNull() == "chunked"
        val max = budget.bodyLimit()
        val data = when {
            !complete -> Body(partial = true)
            bodyless -> Body()
            chunked && transfer.count { it == "chunked" } == 1 -> readChunks(headers, max)
            transfer.isNotEmpty() && response && !chunked -> readToEnd(max, !stream.closed)
            transfer.isNotEmpty() -> Body(partial = true)
            else -> readFixedOrClosing(headers, response, max)
        }
        val content = headers.codings("Content-Encoding")
        val codings = if (bodyless) emptyList() else content + if (chunked) transfer.dropLast(1) else transfer
        val decoded = decodeBody(data, codings, max)
        budget.takeBody(decoded.bytes.size)
        stopped = data.partial || status == 101 || (method == "CONNECT" && status in 200..299)
        return HttpMessage(line, headers, decoded.bytes, data.size,
            decoded.bytes.takeUnless { decoded.unavailable }?.let { bodyText(it, media) }, media,
            data.partial || decoded.corrupt, decoded.limited, decoded.unavailable, verb, path, target, status)
    }

    private fun readHeaders(headers: MutableList<HttpHeader>, limit: Int): Boolean {
        while (pos < limit) {
            val end = lineEnd(bytes, pos, limit)
            if (end < 0) {
                pos = limit
                return false
            }
            val line = ascii(bytes, pos, end)
            pos = end + 2
            if (line.isEmpty()) return true
            val split = line.indexOf(':')
            if (split <= 0 || headers.size == 128) return false
            val name = line.substring(0, split)
            if (!token.matches(name)) return false
            headers.add(HttpHeader(name, line.substring(split + 1).trim()))
        }
        return false
    }

    private fun readFixedOrClosing(headers: List<HttpHeader>, response: Boolean, max: Int): Body {
        val lengths = headers.filter { it.name.equals("Content-Length", true) }.flatMap { it.value.split(',') }
        if (lengths.isEmpty()) return if (response) readToEnd(max, !stream.closed) else Body()
        val lengthsParsed = lengths.map { value ->
            val number = value.trim()
            if (number.isEmpty() || number.any { it !in '0'..'9' }) null else number.toLongOrNull()
        }.distinct()
        val length = lengthsParsed.singleOrNull() ?: return Body(partial = true)
        return readBody(length, max, false)
    }

    private fun readToEnd(max: Int, partial: Boolean) = readBody((bytes.size - pos).toLong(), max, partial)

    private fun readBody(length: Long, max: Int, partial: Boolean): Body {
        val size = minOf(length, (bytes.size - pos).toLong()).toInt()
        val sample = bytes.copyOfRange(pos, pos + minOf(size, max))
        pos += size
        return Body(sample, size, partial || size.toLong() != length)
    }

    private fun readChunks(headers: MutableList<HttpHeader>, max: Int): Body {
        val output = ByteArrayOutputStream()
        var size = 0
        fun result(partial: Boolean) = Body(output.toByteArray(), size, partial)
        while (true) {
            val end = lineEnd(bytes, pos, minOf(bytes.size, pos + 1024))
            if (end < 0) return result(true)
            val number = ascii(bytes, pos, end).substringBefore(';')
            if (number.isEmpty() || number.any { it !in "0123456789abcdefABCDEF" }) return result(true)
            val length = number.toLongOrNull(16) ?: return result(true)
            pos = end + 2
            if (length == 0L) {
                val trailerStart = pos
                val trailers = mutableListOf<HttpHeader>()
                val complete = readHeaders(trailers, minOf(bytes.size, pos + HEADER_LIMIT))
                if (budget.takeHeaders(pos - trailerStart)) headers.addAll(trailers)
                return result(!complete)
            }
            val available = minOf(length, (bytes.size - pos).toLong()).toInt()
            output.write(bytes, pos, minOf(available, max - output.size()))
            pos += available
            size += available
            if (available.toLong() != length || pos + 2 > bytes.size || bytes[pos] != 13.toByte() ||
                bytes[pos + 1] != 10.toByte()) return result(true)
            pos += 2
        }
    }
}

private data class Body(val bytes: ByteArray = ByteArray(0), val size: Int = 0, val partial: Boolean = false)
private data class Decoded(
    val bytes: ByteArray, val limited: Boolean = false, val unavailable: Boolean = false, val corrupt: Boolean = false,
)

private fun decodeBody(data: Body, codings: List<String>, max: Int): Decoded {
    val limited = data.bytes.size < data.size
    val active = codings.filter { it != "identity" }
    if (active.isEmpty() || data.size == 0) return Decoded(data.bytes, limited)
    if (active.size != 1 || active[0] !in setOf("gzip", "x-gzip")) return Decoded(data.bytes, limited, true)

    val output = ByteArrayOutputStream()
    var invalid = false
    var outputLimited = false
    try {
        GZIPInputStream(ByteArrayInputStream(data.bytes)).use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer, 0, minOf(buffer.size, max - output.size() + 1))
                if (count < 0) break
                val remaining = max - output.size()
                output.write(buffer, 0, minOf(count, remaining))
                if (count > remaining) {
                    outputLimited = true
                    break
                }
            }
        }
    } catch (_: IOException) {
        invalid = true
    }
    return if (invalid && output.size() == 0) Decoded(data.bytes, limited, true, !limited)
    else Decoded(output.toByteArray(), limited || outputLimited, corrupt = invalid && !limited)
}

private fun bodyText(bytes: ByteArray, media: String?): String? {
    if (bytes.isEmpty()) return null
    val type = media?.substringBefore(';')?.trim()?.lowercase()
    val textual = type?.let { it.startsWith("text/") || it.endsWith("+json") ||
        it.endsWith("+xml") || it in setOf("application/json", "application/xml", "application/javascript",
        "application/x-www-form-urlencoded") } == true
    if (type != null && !textual) return null
    val charset = media?.let { charsetParameter.find(it)?.groupValues?.get(1) }?.let {
        runCatching { charset(it) }.getOrNull() ?: return null
    } ?: Charsets.UTF_8
    val decoded = bytes.toString(charset)
    return decoded.takeIf { textual || it.none { ch -> ch == '\uFFFD' || (ch.isISOControl() && ch !in "\r\n\t") } }
}

private fun List<HttpHeader>.firstValue(name: String) = firstOrNull { it.name.equals(name, true) }?.value
private fun List<HttpHeader>.codings(name: String) = filter { it.name.equals(name, true) }
    .flatMap { header -> header.value.split(',').map { it.substringBefore(';').trim().lowercase() } }

private fun ascii(bytes: ByteArray, start: Int, end: Int) = String(bytes, start, end - start, Charsets.ISO_8859_1)

private fun lineEnd(bytes: ByteArray, start: Int, end: Int): Int {
    for (index in start until end - 1) {
        if (bytes[index] == 13.toByte() && bytes[index + 1] == 10.toByte()) return index
    }
    return -1
}

internal fun proxyHttpMessage(
    version: String,
    headers: List<HttpHeader>,
    rawBody: ByteArray,
    bodySize: Int,
    previewMissing: Boolean,
    budget: HttpBudget,
    method: String?,
    url: String?,
    status: Int?,
): HttpMessage {
    val contentType = headers.firstValue("Content-Type")
    val encoded = Body(rawBody, maxOf(rawBody.size, bodySize))
    val decoded = decodeBody(encoded, headers.codings("Content-Encoding"), budget.bodyLimit())
    budget.takeBody(decoded.bytes.size)
    val line = if (status == null) "$method $url $version" else "$version $status"
    return HttpMessage(
        line, headers, decoded.bytes, bodySize,
        decoded.bytes.takeUnless { decoded.unavailable }?.let { bodyText(it, contentType) },
        contentType, partial = decoded.corrupt, previewLimited = previewMissing || decoded.limited,
        encodingUnavailable = decoded.unavailable, method = method, target = url, status = status,
    )
}
