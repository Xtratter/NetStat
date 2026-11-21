package io.github.xtratter.netstat.capture

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.NetworkInterface
import java.net.SocketException

internal enum class InterfaceKind { VPN, WIFI, MOBILE, ETHERNET, TUNNEL, OTHER, LOOPBACK }

internal data class CaptureInterface(val name: String, val kind: InterfaceKind)

internal class InterfaceChoices private constructor(val defaultName: String?, val items: List<CaptureInterface>) {
    fun target(selected: String?): CaptureInterface? = items.firstOrNull { it.name == (selected ?: defaultName) }

    companion object {
        fun create(
            defaultName: String?,
            networks: List<CaptureInterface>,
            availableNames: List<String>,
        ): InterfaceChoices {
            val byName = networks.groupBy(CaptureInterface::name)
            val names = (listOfNotNull(defaultName) + byName.keys + availableNames).distinct()
            val items = names.filter(CaptureConfig::isValidInterface).map { name ->
                val reported = byName[name].orEmpty().minByOrNull { it.kind.ordinal }?.kind
                CaptureInterface(name, reported?.takeUnless { it == InterfaceKind.OTHER } ?: inferKind(name))
            }.sortedWith(compareBy({ it.name != defaultName }, { it.kind.ordinal }, { it.name }))
            return InterfaceChoices(defaultName, items)
        }

        private fun inferKind(name: String): InterfaceKind = when {
            name == "lo" -> InterfaceKind.LOOPBACK
            name.startsWith("wlan") -> InterfaceKind.WIFI
            name.startsWith("rmnet") || name.startsWith("ccmni") ||
                name.startsWith("pdp") || name.startsWith("wwan") -> InterfaceKind.MOBILE
            name.startsWith("eth") -> InterfaceKind.ETHERNET
            name.startsWith("tun") || name.startsWith("tap") ||
                name.startsWith("wg") || name.startsWith("ipsec") -> InterfaceKind.TUNNEL
            else -> InterfaceKind.OTHER
        }
    }
}

// Poll a snapshot only while the capture form is visible. Include other connected networks
// in addition to the app's default route so its underlying Wi-Fi or cellular link is selectable.
@Suppress("DEPRECATION")
internal fun discoverInterfaces(connectivity: ConnectivityManager?): InterfaceChoices {
    val available = try {
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().mapNotNull { network ->
            if (runCatching { network.isUp }.getOrDefault(false)) network.name else null
        }
    } catch (_: SocketException) {
        emptyList()
    }
    if (connectivity == null) return InterfaceChoices.create(null, emptyList(), available)
    val active = connectivity.activeNetwork
    val defaultName = active?.let { connectivity.getLinkProperties(it)?.interfaceName }
    val networks = (listOfNotNull(active) + connectivity.allNetworks).distinct().mapNotNull { network ->
        val name = connectivity.getLinkProperties(network)?.interfaceName ?: return@mapNotNull null
        val caps = connectivity.getNetworkCapabilities(network)
        val kind = when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true -> InterfaceKind.VPN
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> InterfaceKind.WIFI
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> InterfaceKind.MOBILE
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> InterfaceKind.ETHERNET
            else -> InterfaceKind.OTHER
        }
        CaptureInterface(name, kind)
    }
    return InterfaceChoices.create(defaultName, networks, available)
}
