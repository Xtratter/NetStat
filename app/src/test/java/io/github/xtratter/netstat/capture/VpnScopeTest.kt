package io.github.xtratter.netstat.capture

import org.junit.Assert.*
import org.junit.Test

class VpnScopeTest {
    @Test fun androidPackageScopeKeepsPacketsWithUnknownUidButRejectsOtherOwners() {
        val config = CaptureConfig("vpn", 10042, "Example", CaptureMode.VPN, "com.example.client")
        assertTrue(config.acceptsUid(10042))
        assertTrue(config.acceptsUid(null))
        assertFalse(config.acceptsUid(10043))
        assertFalse(CaptureConfig("lo", 10042).acceptsUid(null))
    }

    @Test fun vpnCannotClaimThatAUidWasFilteredWithoutAnAllowlistedPackage() {
        assertThrows(IllegalArgumentException::class.java) {
            CaptureConfig("vpn", 10042, mode = CaptureMode.VPN)
        }
        assertTrue(CaptureConfig("vpn", null, mode = CaptureMode.VPN).acceptsUid(null))
    }
}
