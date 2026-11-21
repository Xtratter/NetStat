package io.github.xtratter.netstat.capture

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicReference

private const val VPN_MTU = 1500

internal object VpnNative {
    val supported by lazy {
        runCatching { System.loadLibrary("netstatvpn") }.isSuccess
    }

    external fun run(fd: Int, mtu: Int, callbacks: VpnCallbacks): Int
}

internal interface VpnCallbacks {
    fun protectSocket(fd: Int): Boolean
    fun shouldRun(): Boolean
    fun onPacket(packet: ByteArray, outgoing: Boolean, dropped: Int): Boolean
}

internal class VpnCapture(
    private val service: VpnService,
    private val config: CaptureConfig,
    private val update: (CaptureSnapshot) -> Unit,
) : CaptureWorker {
    private val stopReason = AtomicReference<CaptureEnd?>()
    private val archive = CaptureArchive(service.noBackupFilesDir)
    private val connectivity = service.getSystemService(ConnectivityManager::class.java)
    private var detail: String? = null

    override fun stop(reason: CaptureEnd) {
        stopReason.compareAndSet(null, reason)
    }

    override fun run(): CaptureReport {
        val started = System.currentTimeMillis()
        var draft: CaptureArchive.Draft? = null
        var ledger: CaptureLedger? = null
        try {
            if (stopReason.get() == null) {
                val network = underlyingNetwork()
                val builder = vpnBuilder(network)
                val tunnel = builder.establish() ?: throw IOException("Android did not establish the VPN")
                tunnel.use { tun ->
                    try {
                        draft = archive.begin(config, started)
                        FileOutputStream(checkNotNull(draft).packetFile).use { file ->
                            val writer = RawPcapWriter(file, CAPTURE_BYTES_LIMIT)
                            val capture = CaptureLedger(config, writer)
                            ledger = capture
                            update(capture.snapshot())
                            try {
                                val result = VpnNative.run(tun.fd, VPN_MTU, Recorder(network, capture))
                                if (result != 0 && stopReason.get() == null) {
                                    fail(CaptureEnd.VPN_FAILED, "VPN forwarding stopped (errno $result)")
                                }
                            } finally {
                                file.channel.truncate(writer.completedBytes)
                                file.fd.sync()
                            }
                        }
                    } catch (error: IOException) {
                        fail(CaptureEnd.STORAGE_FAILED, error.message)
                    }
                }
            }
        } catch (error: Exception) {
            fail(CaptureEnd.VPN_FAILED, error.message)
        }

        val report = CaptureReport(
            config, started, System.currentTimeMillis(), ledger?.snapshot() ?: CaptureSnapshot(),
            stopReason.get() ?: CaptureEnd.INTERRUPTED, detail, draft?.id,
        )
        return try {
            draft?.let { archive.finish(it, report) }
            report
        } catch (error: IOException) {
            report.copy(reason = CaptureEnd.STORAGE_FAILED, detail = error.message)
        }
    }

    private fun fail(end: CaptureEnd, message: String?) {
        if (stopReason.compareAndSet(null, end)) detail = message?.take(400)
    }

    private fun underlyingNetwork(): Network {
        val manager = connectivity ?: throw IOException("Android networking is unavailable")
        val network = manager.activeNetwork ?: throw IOException("Connect to Wi-Fi or mobile data")
        if (manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
            throw IOException("Another VPN is still active")
        }
        return network
    }

    private fun vpnBuilder(network: Network): VpnService.Builder {
        val dnsServers = connectivity?.getLinkProperties(network)?.dnsServers.orEmpty()
            .filterNot { it.isLinkLocalAddress || it.isAnyLocalAddress || it.isLoopbackAddress }
        if (dnsServers.isEmpty()) throw IOException("The active network supplied no usable DNS servers")
        val builder = service.Builder().setSession("NetStat")
            .addAddress("198.18.0.1", 32).addRoute("0.0.0.0", 0)
            .addAddress("fd00:4e53::1", 128).addRoute("::", 0)
            .setMtu(VPN_MTU).setBlocking(false).setMetered(false).setUnderlyingNetworks(arrayOf(network))
        dnsServers.forEach { builder.addDnsServer(it) }
        val selected = config.packageName
        if (selected != null) {
            val actualUid = service.packageManager.getApplicationInfo(selected, 0).uid
            if (actualUid != config.uid || selected == service.packageName) {
                throw IOException("The selected app changed or is NetStat")
            }
            builder.addAllowedApplication(selected)
        } else {
            builder.addDisallowedApplication(service.packageName)
        }
        return builder
    }

    private inner class Recorder(
        private val network: Network,
        private val capture: CaptureLedger,
    ) : VpnCallbacks {
        private val start = SystemClock.elapsedRealtime()
        private var nextPublish = start + 500
        private var nextNetworkCheck = start + 1000
        private val owners = LinkedHashMap<ConnectionKey, CachedOwner>()

        override fun protectSocket(fd: Int): Boolean = try {
            if (!service.protect(fd)) false
            else {
                ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) }
                true
            }
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }

        override fun shouldRun(): Boolean {
            val now = SystemClock.elapsedRealtime()
            if (now - start >= CAPTURE_DURATION_SECONDS * 1000L) stop(CaptureEnd.TIME_LIMIT)
            if (stopReason.get() == null && now >= nextNetworkCheck) {
                if (connectivity?.getNetworkCapabilities(network) == null) {
                    fail(CaptureEnd.INTERRUPTED, null)
                }
                nextNetworkCheck = now + 1000
            }
            return stopReason.get() == null
        }

        override fun onPacket(packet: ByteArray, outgoing: Boolean, dropped: Int): Boolean {
            if (stopReason.get() != null) return false
            val wallTime = System.currentTimeMillis()
            val now = SystemClock.elapsedRealtime()
            val endpoints = endpointsOf(packet)
            val owner = endpoints?.let { uidFor(it, outgoing, now) }
            val frame = PcapdFrame(wallTime / 1000, (wallTime % 1000).toInt() * 1000, dropped.toLong(), owner, outgoing, packet)
            try {
                if (capture.accept(frame) == AcceptResult.LIMIT) stop(CaptureEnd.SIZE_LIMIT)
            } catch (error: IOException) {
                fail(CaptureEnd.STORAGE_FAILED, error.message)
            }
            if (now >= nextPublish) {
                update(capture.snapshot())
                nextPublish = now + 500
            }
            return stopReason.get() == null
        }

        private fun uidFor(endpoints: PacketEndpoints, outgoing: Boolean, now: Long): Int? {
            val local = if (outgoing) endpoints.source else endpoints.destination
            val remote = if (outgoing) endpoints.destination else endpoints.source
            val localPort = local.port ?: return null
            val remotePort = remote.port ?: return null
            val key = endpoints.key
            val old = owners[key]
            if (!endpoints.startsTcp && old != null && now < old.expires) return old.uid
            val result = try {
                connectivity?.getConnectionOwnerUid(
                    endpoints.protocol, InetSocketAddress(local.address, localPort),
                    InetSocketAddress(remote.address, remotePort),
                )?.takeIf { it >= 0 }
            } catch (_: SecurityException) {
                null
            } catch (_: IllegalArgumentException) {
                null
            }
            if (owners.size >= 2048) owners.remove(owners.keys.first())
            owners[key] = CachedOwner(result, now + if (result == null) 250 else 3_000)
            return result
        }
    }
}

private data class CachedOwner(val uid: Int?, val expires: Long)


@Suppress("DEPRECATION")
internal fun hasActiveVpn(connectivity: ConnectivityManager?): Boolean {
    if (connectivity == null) return false
    return (listOfNotNull(connectivity.activeNetwork) + connectivity.allNetworks).distinct().any {
        connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }
}
