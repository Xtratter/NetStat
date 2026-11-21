package io.github.xtratter.netstat.capture

import android.util.AtomicFile
import android.util.Log
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

internal class CaptureArchive(noBackupFiles: File) {
    private val root = File(noBackupFiles, "capture")
    private val current = AtomicFile(File(root, "pending.json"))
    private val latest = AtomicFile(File(root, "latest.json"))

    data class Draft(val id: String, val packetFile: File)

    fun begin(config: CaptureConfig, started: Long): Draft {
        if (!root.mkdirs() && !root.isDirectory) throw IOException("Cannot open the capture directory")
        val id = UUID.randomUUID().toString()
        current.write(JSONObject().put("id", id).put("config", config.toJson()).put("started", started))
        return Draft(id, File(root, "capture-$id.pcap"))
    }

    fun finish(draft: Draft, report: CaptureReport) {
        latest.write(report.toJson().put("id", draft.id))
        current.delete()
        discardOtherCaptures(draft.packetFile.name)
    }

    fun restore(): CaptureReport? {
        val stored = latest.read()
        val lastReport = stored?.let { runCatching { it.toReport() }.getOrNull() }
        val pending = current.read()
        if (pending == null || pending.optString("id") == stored?.optString("id")) {
            current.delete()
            val keepId = stored?.optString("id").takeIf { lastReport != null }
            discardOtherCaptures(keepId?.let { "capture-$it.pcap" })
            return lastReport
        }

        val config = runCatching { pending.getJSONObject("config").toConfig() }.getOrNull()
        val id = pending.optString("id")
        if (config != null && runCatching { UUID.fromString(id).toString() == id }.getOrDefault(false)) {
            val packetFile = File(root, "capture-$id.pcap")
            val started = pending.optLong("started")
            val interrupted = CaptureReport(config, started, System.currentTimeMillis(), CaptureSnapshot(), CaptureEnd.INTERRUPTED)
            try {
                val prefix = recoverPcapPrefix(packetFile)
                val snapshot = CaptureSnapshot(packets = prefix?.packets ?: 0, payloadBytes = prefix?.payloadBytes ?: 0)
                val report = interrupted.copy(snapshot = snapshot)
                latest.write(report.toJson().put("id", id))
                current.delete()
                discardOtherCaptures(packetFile.name.takeIf { prefix != null })
                return report
            } catch (error: IOException) {
                // Keep the pending entry and file intact so the next launch can retry.
                Log.w("NetStat", "Cannot recover interrupted capture", error)
                return interrupted
            }
        }

        current.delete()
        val keepId = stored?.optString("id")?.takeIf { lastReport != null }
        discardOtherCaptures(keepId?.let { "capture-$it.pcap" })
        return lastReport
    }

    private fun discardOtherCaptures(keep: String?) {
        root.listFiles()?.forEach { file ->
            if (file.name != keep && file.name.startsWith("capture-") && file.extension == "pcap") {
                file.delete()
            }
        }
    }
}

private fun AtomicFile.write(json: JSONObject) {
    val stream = startWrite()
    try {
        stream.write(json.toString().toByteArray(Charsets.UTF_8))
        finishWrite(stream)
    } catch (error: Exception) {
        failWrite(stream)
        throw error
    }
}

private fun AtomicFile.read(): JSONObject? = try {
    openRead().bufferedReader(Charsets.UTF_8).use { JSONObject(it.readText()) }
} catch (_: FileNotFoundException) {
    null
} catch (error: Exception) {
    Log.w("NetStat", "Cannot read the capture archive", error)
    null
}

private fun CaptureConfig.toJson() = JSONObject()
    .put("interface", interfaceName).put("uid", uid ?: JSONObject.NULL).put("label", label ?: JSONObject.NULL)

private fun JSONObject.toConfig() = CaptureConfig(
    getString("interface"), optionalInt("uid"), optionalString("label"),
)

private fun Endpoint.toJson() = JSONObject().put("address", address).put("port", port ?: JSONObject.NULL)

private fun JSONObject.toEndpoint() = Endpoint(getString("address"), optionalInt("port"))

private fun ConnectionSummary.toJson() = JSONObject()
    .put("protocol", key.protocol).put("first", key.first.toJson()).put("second", key.second.toJson())
    .put("firstSeen", firstSeenMillis).put("lastSeen", lastSeenMillis)
    .put("rx", received).put("tx", sent).put("packets", packets)
    .put("uid", uid ?: JSONObject.NULL).put("unknown", unknownPackets).put("confidence", confidence.name)

private fun JSONObject.toConnection() = ConnectionSummary(
    ConnectionKey(getInt("protocol"), getJSONObject("first").toEndpoint(), getJSONObject("second").toEndpoint()),
    getLong("firstSeen"), getLong("lastSeen"), getLong("rx"), getLong("tx"), getInt("packets"),
    optionalInt("uid"), getInt("unknown"), UidConfidence.valueOf(getString("confidence")),
)

private fun CaptureReport.toJson() = JSONObject()
    .put("config", config.toJson()).put("started", startedMillis).put("ended", endedMillis)
    .put("reason", reason.name).put("detail", detail ?: JSONObject.NULL)
    .put("packets", snapshot.packets).put("bytes", snapshot.payloadBytes)
    .put("uidExcluded", snapshot.uidExcluded).put("malformed", snapshot.malformed)
    .put("unlisted", snapshot.unlistedPackets).put("drops", snapshot.drops ?: JSONObject.NULL)
    .put("connections", JSONArray().also { array -> snapshot.connections.forEach { array.put(it.toJson()) } })

private fun JSONObject.toReport(): CaptureReport {
    val items = getJSONArray("connections")
    val snapshot = CaptureSnapshot(
        getInt("packets"), getLong("bytes"), getInt("uidExcluded"), getInt("malformed"), getInt("unlisted"),
        if (isNull("drops")) null else getLong("drops"),
        List(minOf(items.length(), CAPTURE_CONNECTION_LIMIT)) { items.getJSONObject(it).toConnection() },
    )
    return CaptureReport(
        getJSONObject("config").toConfig(), getLong("started"), getLong("ended"), snapshot,
        CaptureEnd.valueOf(getString("reason")), optionalString("detail"),
    )
}

private fun JSONObject.optionalInt(key: String): Int? = if (isNull(key)) null else getInt(key)
private fun JSONObject.optionalString(key: String): String? = if (isNull(key)) null else getString(key)
