package io.github.xtratter.netstat.capture

import android.content.Context
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Build
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.NetworkInterface
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

internal class PcapdCapture(
    private val context: Context,
    private val config: CaptureConfig,
    private val onSnapshot: (CaptureSnapshot) -> Unit,
) {
    private val stopReason = AtomicReference<CaptureEnd?>()
    private val archive = CaptureArchive(context.noBackupFilesDir)
    private var finalDrops: Long? = null
    private var helperExitUnconfirmed = false

    fun stop(reason: CaptureEnd = CaptureEnd.USER_STOPPED) {
        stopReason.compareAndSet(null, reason)
    }

    fun run(): CaptureReport {
        val started = System.currentTimeMillis()
        var draft: CaptureArchive.Draft? = null
        var ledger: CaptureLedger? = null
        val end = try {
            checkStop()
            val binary = verifiedHelper(context)
            draft = storage { archive.begin(config, started) }
            val packetFile = draft.packetFile
            try {
                storage { FileOutputStream(packetFile) }.use { output ->
                    val writer = storage { RawPcapWriter(output, CAPTURE_BYTES_LIMIT) }
                    val current = CaptureLedger(config, writer)
                    ledger = current
                    try {
                        capture(binary, current)
                    } finally {
                        // An interrupted or failed write may have left a partial last record.
                        storage {
                            output.channel.truncate(writer.completedBytes)
                            output.fd.sync()
                        }
                    }
                }
            } catch (failure: EndOfCapture) {
                if (failure.reason == CaptureEnd.STORAGE_FAILED && !validPrefix(packetFile, ledger?.snapshot())) {
                    packetFile.delete()
                }
                throw failure
            }
        } catch (end: EndOfCapture) {
            end
        } catch (error: Exception) {
            Log.w("NetStat", "Capture failed", error)
            EndOfCapture(CaptureEnd.ROOT_FAILED, error.message)
        }
        val snapshot = ledger?.snapshot() ?: CaptureSnapshot()
        val sample = finalDrops
        val report = CaptureReport(
            config, started, System.currentTimeMillis(),
            if (sample == null) snapshot else snapshot.copy(drops = maxOf(snapshot.drops ?: 0L, sample)),
            if (helperExitUnconfirmed) CaptureEnd.INTERRUPTED else end.reason,
            end.message?.take(400),
            draft?.id,
        )
        return try {
            draft?.let { archive.finish(it, report) }
            report
        } catch (error: Exception) {
            Log.w("NetStat", "Cannot save capture report", error)
            report.copy(reason = CaptureEnd.STORAGE_FAILED, detail = error.message?.take(400))
        }
    }

    private fun capture(binary: File, ledger: CaptureLedger): Nothing {
        val working = Files.createTempDirectory(context.cacheDir.toPath(), "np-").toFile()
        val socketPath = File(working, "pcapsock")
        try {
            if (socketPath.path.toByteArray().size > 107) {
                throw EndOfCapture(CaptureEnd.ROOT_FAILED, "The private socket path exceeds the Unix limit")
            }
            LocalSocket().use { bound ->
                bound.bind(LocalSocketAddress(socketPath.path, LocalSocketAddress.Namespace.FILESYSTEM))
                LocalServerSocket(bound.fileDescriptor).use { listener ->
                    checkStop()
                    val process = launchHelper(binary, working)
                    val logs = HelperLog(process.inputStream, config.interfaceName)
                    try {
                        val deadline = SystemClock.elapsedRealtime() + START_MILLIS
                        waitForPeer(listener, process, logs, deadline).use { connection ->
                            if (connection.peerCredentials.uid != 0) {
                                throw EndOfCapture(CaptureEnd.ROOT_FAILED, "The helper has an unexpected peer UID")
                            }
                            while (!logs.ready) {
                                checkStartup(process, logs, deadline)
                                Thread.sleep(40)
                            }
                            record(connection, ledger)
                        }
                    } catch (error: EndOfCapture) {
                        if (error.reason == CaptureEnd.ROOT_FAILED || error.reason == CaptureEnd.BAD_STREAM) {
                            throw EndOfCapture(error.reason, logs.diagnostic() ?: error.message)
                        }
                        throw error
                    } finally {
                        helperExitUnconfirmed = !stopHelper(process)
                        finalDrops = logs.drops
                    }
                }
            }
        } finally {
            socketPath.delete()
            working.delete()
        }
    }

    private fun launchHelper(binary: File, working: File): Process {
        val args = mutableListOf(
            "/system/bin/timeout", "-k", "2", (CAPTURE_DURATION_SECONDS + 15).toString(),
            binary.absolutePath, "-i", config.interfaceName,
        )
        config.uid?.let { args.addAll(listOf("-u", it.toString())) }
        val command = "cd ${quoteShell(working.absolutePath)} && exec ${args.joinToString(" ", transform = ::quoteShell)}"
        return try {
            ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
        } catch (error: IOException) {
            throw EndOfCapture(CaptureEnd.ROOT_FAILED, error.message)
        }
    }

    private fun waitForPeer(
        listener: LocalServerSocket,
        process: Process,
        logs: HelperLog,
        deadline: Long,
    ): LocalSocket {
        while (true) {
            checkStartup(process, logs, deadline)
            if (readyToRead(listener.fileDescriptor)) return listener.accept()
        }
    }

    private fun checkStartup(process: Process, logs: HelperLog, deadline: Long) {
        checkStop()
        if (!process.isAlive || SystemClock.elapsedRealtime() >= deadline) {
            throw EndOfCapture(CaptureEnd.ROOT_FAILED, logs.diagnostic())
        }
    }

    private fun record(connection: LocalSocket, ledger: CaptureLedger): Nothing {
        val started = SystemClock.elapsedRealtime()
        val deadline = started + CAPTURE_DURATION_SECONDS * 1000L
        val initialInterface = interfaceIndex()
        var nextInterfaceCheck = started + 2_000
        val input = CaptureInput(connection) {
            checkStop()
            val now = SystemClock.elapsedRealtime()
            if (now >= deadline) throw EndOfCapture(CaptureEnd.TIME_LIMIT)
            if (initialInterface != null && now >= nextInterfaceCheck) {
                if (interfaceIndex() != initialInterface) throw EndOfCapture(CaptureEnd.INTERRUPTED)
                nextInterfaceCheck = now + 2_000
            }
        }
        onSnapshot(ledger.snapshot())
        var nextSnapshot = started + 500
        while (true) {
            val frame = try {
                readPcapdFrame(input)
            } catch (error: IOException) {
                checkStop()
                throw EndOfCapture(CaptureEnd.BAD_STREAM, error.message)
            } ?: run {
                checkStop()
                throw EndOfCapture(CaptureEnd.BAD_STREAM)
            }
            checkStop()
            if (storage { ledger.accept(frame) } == AcceptResult.LIMIT) {
                throw EndOfCapture(CaptureEnd.SIZE_LIMIT)
            }
            val now = SystemClock.elapsedRealtime()
            if (now >= nextSnapshot) {
                onSnapshot(ledger.snapshot())
                nextSnapshot = now + 500
            }
        }
    }

    private fun interfaceIndex(): Int? = runCatching {
        NetworkInterface.getByName(config.interfaceName)?.index
    }.getOrNull()

    private fun checkStop() {
        stopReason.get()?.let { throw EndOfCapture(it) }
    }

    companion object {
        private const val START_MILLIS = 10_000L
        private const val HELPER_SHA256 = "4cc86aa41502882ec3a6ad4dab0d6c64aea3ee5d0efa23a7bdc208da646c3697"

        fun isSupported(context: Context): Boolean =
            Build.SUPPORTED_ABIS.contains("arm64-v8a") && helperFile(context).isFile

        private fun helperFile(context: Context) = File(context.applicationInfo.nativeLibraryDir, "libpcapd.so")

        private fun verifiedHelper(context: Context): File {
            if (!isSupported(context)) throw EndOfCapture(CaptureEnd.UNAVAILABLE)
            val file = helperFile(context)
            val sha = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val length = input.read(buffer)
                    if (length < 0) break
                    sha.update(buffer, 0, length)
                }
            }
            if (sha.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) } != HELPER_SHA256) {
                throw EndOfCapture(CaptureEnd.UNAVAILABLE, "The packaged pcapd fingerprint does not match")
            }
            return file
        }
    }
}

private class EndOfCapture(val reason: CaptureEnd, detail: String? = null) : Exception(detail)

private inline fun <T> storage(block: () -> T): T = try {
    block()
} catch (error: IOException) {
    throw EndOfCapture(CaptureEnd.STORAGE_FAILED, error.message)
} catch (error: SecurityException) {
    throw EndOfCapture(CaptureEnd.STORAGE_FAILED, error.message)
}

private fun validPrefix(file: File, snapshot: CaptureSnapshot?): Boolean {
    if (snapshot == null) return false
    val expectedLength = 24 + snapshot.packets * 16L + snapshot.payloadBytes
    return file.length() == expectedLength
}

private fun quoteShell(value: String) = "'" + value.replace("'", "'\"'\"'") + "'"

private fun readyToRead(fd: FileDescriptor): Boolean {
    val event = StructPollfd().apply {
        this.fd = fd
        events = (OsConstants.POLLIN or OsConstants.POLLHUP or OsConstants.POLLERR).toShort()
    }
    return try {
        Os.poll(arrayOf(event), 150) > 0
    } catch (error: ErrnoException) {
        if (error.errno == OsConstants.EINTR) false else throw IOException("Polling pcapd failed", error)
    }
}

private class CaptureInput(connection: LocalSocket, private val check: () -> Unit) : InputStream() {
    private val fd = connection.fileDescriptor
    private val source = connection.inputStream
    private val single = ByteArray(1)

    override fun read(): Int {
        val count = read(single, 0, 1)
        return if (count < 0) -1 else single[0].toInt() and 0xFF
    }

    override fun read(buffer: ByteArray, offset: Int, size: Int): Int {
        if (size == 0) return 0
        while (true) {
            check()
            if (readyToRead(fd)) {
                val count = source.read(buffer, offset, size)
                if (count != 0) return count
            }
        }
    }
}

private class HelperLog(source: InputStream, interfaceName: String) {
    private val lines = ArrayDeque<String>()
    private val readyPattern = Regex("""(?:^|\s)${Regex.escape(interfaceName)}\(\d+\): datalink=""")
    private val dropPattern = Regex("""Pkts: \d+ rcvd, (\d+) drops""")

    @Volatile var ready = false
        private set

    @Volatile var drops: Long? = null
        private set

    init {
        thread(isDaemon = true, name = "pcapd-log") {
            try {
                source.bufferedReader().useLines { stream -> stream.forEach(::add) }
            } catch (_: IOException) {
                // Closing the helper also closes its diagnostic pipe.
            }
        }
    }

    @Synchronized private fun add(line: String) {
        if (readyPattern.containsMatchIn(line)) ready = true
        dropPattern.find(line)?.groupValues?.get(1)?.toLongOrNull()?.let { drops = it }
        if (lines.size == 12) lines.removeFirst()
        lines.addLast(line.take(300))
    }

    @Synchronized fun diagnostic(): String? =
        lines.lastOrNull { "failed" in it.lowercase() || "denied" in it.lowercase() || "error" in it.lowercase() }
            ?: lines.lastOrNull()
}

private fun stopHelper(process: Process): Boolean {
    if (process.waitFor(800, TimeUnit.MILLISECONDS)) return true
    process.destroy()
    if (process.waitFor(600, TimeUnit.MILLISECONDS)) return true
    process.destroyForcibly()
    return process.waitFor(500, TimeUnit.MILLISECONDS)
}
