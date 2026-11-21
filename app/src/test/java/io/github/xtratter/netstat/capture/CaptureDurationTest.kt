package io.github.xtratter.netstat.capture

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class CaptureDurationTest {
    @Test fun oldSessionUsesTheThreeMinuteDefault() {
        val legacy = JSONObject("""{"interface":"tun0","uid":null,"label":null}""")
        val config = legacy.toConfig()
        assertEquals(CaptureMode.ROOT, config.mode)
        assertEquals(180, config.duration.seconds)
        assertEquals(config, config.toJson().toConfig())
    }

    @Test fun savedVpnSessionRestoresTheThirtyMinuteSelection() {
        val config = CaptureConfig("vpn", 10005, "Example", CaptureMode.VPN,
            "com.example", CaptureDuration.EXTENDED)
        val restored = config.toJson().toConfig()
        assertEquals(1_800, restored.duration.seconds)
        assertEquals(config, restored)
    }
}
