package io.github.xtratter.netstat.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CaptureInterfacesTest {
    @Test fun defaultVpnAndMappedTransportsAppearBeforeTechnicalInterfaces() {
        val discovered = listOf(
            CaptureInterface("tun7", InterfaceKind.VPN),
            CaptureInterface("wifi2", InterfaceKind.WIFI),
        )
        val options = InterfaceChoices.create("tun7", discovered, listOf(
            "lo", "rmnet_data0", "wifi2", "eth0", "tun7", "any",
        ))
        assertEquals(listOf("tun7", "wifi2", "rmnet_data0", "eth0", "lo"), options.items.map { it.name })
        assertEquals(InterfaceKind.WIFI, options.items[1].kind)
        assertEquals(InterfaceKind.MOBILE, options.items[2].kind)
        assertEquals("tun7", options.target(null)?.name)
    }

    @Test fun manualChoiceStaysFixedAcrossNetworkChanges() {
        val options = InterfaceChoices.create("rmnet0", emptyList(), listOf("rmnet0", "wlan0"))
        assertEquals("wlan0", options.target("wlan0")?.name)
        assertNull(options.target("tun0"))
        assertEquals("rmnet0", options.target(null)?.name)
    }

    @Test fun loopbackIsAvailableWithoutBecomingTheDefaultRoute() {
        val options = InterfaceChoices.create(null, emptyList(), listOf("lo"))
        assertEquals(InterfaceKind.LOOPBACK, options.items.single().kind)
        assertNull(options.target(null))
    }
}
