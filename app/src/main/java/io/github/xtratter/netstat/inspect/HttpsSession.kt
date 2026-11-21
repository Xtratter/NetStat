package io.github.xtratter.netstat.inspect

import io.github.xtratter.netstat.capture.Endpoint
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.URI
import java.util.Base64

private const val SESSION_LIMIT = 8 * 1024 * 1024
private const val PREVIEW_LIMIT = 256 * 1024
private val versions = setOf("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0")
private val hostName = Regex("[a-zA-Z0-9.-]{1,253}")
private val methodToken = Regex("[!#\$%&'*+.^_`|~0-9A-Za-z-]{1,64}")

internal data class HttpsSession(
    val client: String,
    val host: String,
    val port: Int,
    val clientTlsFailures: Int,
    val serverTlsFailures: Int,
    val clientTlsWithoutHttp: Int,
    val dialogues: HttpDialogues,
)

internal fun readHttpsSession(input: InputStream): HttpsSession {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(16384)
    while (true) {
        val count = input.read(buffer)
        if (count < 0) break
        if (output.size() + count > SESSION_LIMIT) throw IOException("HTTPS session is too large")
        output.write(buffer, 0, count)
    }
    val text = output.toString(Charsets.UTF_8.name())
    try {
        checkNesting(text)
        return parseHttpsSession(JSONObject(text))
    } catch (error: JSONException) {
        throw IOException("Invalid HTTPS session", error)
    } catch (error: IllegalArgumentException) {
        throw IOException("Invalid HTTPS session", error)
    }
}

private fun parseHttpsSession(root: JSONObject): HttpsSession {
    require(root.getString("format") == "netstat-https" && root.getInt("version") == 1)
    val client = root.getString("client").also { require(it.isNotBlank() && it.length <= 120) }
    val host = root.getString("host").also { require(hostName.matches(it)) }
    val port = root.getInt("port").also { require(it in 1..65535) }
    val flows = root.getJSONArray("flows")
    val budget = HttpBudget()
    val ids = HashSet<String>()
    var limited = root.optBoolean("limited")
    val exchanges = buildList {
        for (index in 0 until flows.length()) {
            if (budget.full || index == 512) {
                limited = true
                break
            }
            val flow = flows.getJSONObject(index)
            val id = flow.getString("id")
            require(id.length in 1..128 && ids.add(id))
            val request = flow.getJSONObject("request")
            val url = request.getString("url").also { require(it.length <= 8192) }
            val destination = runCatching { URI(url) }.getOrNull()
            require(destination != null && destination.scheme.equals("https", true) &&
                destination.host.equals(host, true) && destination.userInfo == null &&
                (if (destination.port == -1) 443 else destination.port) == port)
            val method = request.getString("method").also { require(methodToken.matches(it)) }
            val requestMessage = request.message(budget, method, url, null)
            if (requestMessage == null) {
                limited = true
                break
            }
            val response = flow.optJSONObject("response")
            val status = response?.getInt("status")?.also { require(it in 100..599) }
            val reply = response?.message(budget, null, null, status)
            add(HttpExchange(
                Endpoint(client, null), Endpoint(host, port), requestMessage, listOfNotNull(reply),
                reply == null || requestMessage.partial || reply.partial,
            ))
        }
    }
    return HttpsSession(
        client, host, port, root.optInt("clientTlsFailures").coerceAtLeast(0),
        root.optInt("serverTlsFailures").coerceAtLeast(0), root.optInt("clientTlsWithoutHttp").coerceAtLeast(0),
        HttpDialogues(exchanges, limited || budget.limited),
    )
}

private fun JSONObject.message(budget: HttpBudget, method: String?, url: String?, status: Int?): HttpMessage? {
    val version = getString("version").also { require(it in versions) }
    val list = optJSONArray("headers")
    val count = list?.length() ?: 0
    require(count <= 128)
    val headers = List(count) { index ->
        val header = checkNotNull(list).getJSONArray(index)
        val name = header.getString(0)
        val value = header.getString(1)
        require(name.length in 1..256 && value.length <= 32 * 1024)
        HttpHeader(name, value)
    }
    if (!budget.takeHeaders(headers.sumOf { it.name.length + it.value.length + 4 } + (url?.length ?: 0) + 32)) return null
    val encoded = optString("body")
    require(encoded.length <= ((PREVIEW_LIMIT + 2) / 3) * 4)
    val bytes = Base64.getDecoder().decode(encoded)
    val size = optInt("size", bytes.size)
    require(bytes.size <= PREVIEW_LIMIT && size >= bytes.size)
    val preview = bytes.copyOf(minOf(bytes.size, budget.bodyLimit()))
    return proxyHttpMessage(version, headers, preview, size, optBoolean("previewMissing"), budget, method, url, status)
}

// Android's JSON parser is recursive. Reject deeply nested input before constructing objects.
private fun checkNesting(text: String) {
    var depth = 0
    var quoted = false
    var escaped = false
    var previous = ' '
    for (char in text) {
        if (quoted) {
            if (escaped) escaped = false
            else if (char == '\\') escaped = true
            else if (char == '"') {
                quoted = false
                previous = '"'
            }
            continue
        }
        if (char in " \r\n\t") continue
        if (previous == '"') require(char in ":,}]")
        when (char) {
            '"' -> {
                require(previous in " {[:,")
                quoted = true
            }
            '{', '[' -> require(++depth <= 12)
            '}', ']' -> require(--depth >= 0)
            else -> require(char in ",:-+.eE0123456789truefalsn")
        }
        previous = char
    }
    require(!quoted && depth == 0)
}
