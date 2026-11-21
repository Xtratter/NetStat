package io.github.xtratter.netstat.probe;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class ProbeActivity extends Activity {
    private static final String TAG = "NetStatProbe";
    private static final String HOST = "10.0.2.2";
    private static final byte[] HTTP_BODY = "netstat-acceptance".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DNS_QUERY = {
        0x01, 0x23, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x04, 't', 'e', 's', 't', 0, 0, 1, 0, 1
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if (getIntent().getBooleanExtra("takeVpn", false)) {
            Intent consent = VpnService.prepare(this);
            if (consent != null) startActivityForResult(consent, 1);
            else finish();
            return;
        }
        final String phase = getIntent().getStringExtra("phase");
        new Thread(() -> {
            try {
                testHttp();
                testDns();
                Log.i(TAG, "OK " + phase);
            } catch (Exception error) {
                Log.e(TAG, "FAILED " + phase, error);
            } finally {
                finish();
            }
        }).start();
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        finish();
    }

    private static void testHttp() throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL("http://" + HOST + ":18780/control").openConnection();
        connection.setConnectTimeout(3000);
        connection.setReadTimeout(3000);
        try (var body = connection.getInputStream()) {
            if (connection.getResponseCode() != 200 || !Arrays.equals(body.readAllBytes(), HTTP_BODY)) {
                throw new IllegalStateException("unexpected HTTP response");
            }
        } finally {
            connection.disconnect();
        }
    }

    private static void testDns() throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName(HOST), 18781);
            socket.setSoTimeout(3000);
            socket.send(new DatagramPacket(DNS_QUERY, DNS_QUERY.length));
            byte[] data = new byte[64];
            DatagramPacket response = new DatagramPacket(data, data.length);
            socket.receive(response);
            if (response.getLength() < 12 || data[0] != DNS_QUERY[0] || data[1] != DNS_QUERY[1] || (data[2] & 0x80) == 0) {
                throw new IllegalStateException("unexpected DNS response");
            }
        }
    }
}
