package io.github.xtratter.netstat.inspect

import java.io.IOException
import org.junit.Assert.*
import org.junit.Test

class HttpsSessionTest {
    @Test fun keepsParallelHttp2ExchangesPairedByProxyFlow() {
        val session = read("""{"format":"netstat-https","version":1,"client":"Test client","host":"example.test","port":443,
            "clientTlsFailures":1,"serverTlsFailures":0,"limited":false,"flows":[
              {"id":"two","request":{"method":"GET","url":"https://example.test/two","version":"HTTP/2.0"},
               "response":{"status":204,"version":"HTTP/2.0"}},
              {"id":"one","request":{"method":"POST","url":"https://example.test/one","version":"HTTP/2.0"},
               "response":{"status":200,"version":"HTTP/2.0","headers":[["Content-Type","text/plain"]],"body":"bmV0c3RhdC1oZWFsdGh5","size":15}}
            ]}""")
        assertEquals("Test client", session.client)
        assertEquals(1, session.clientTlsFailures)
        assertEquals(204, session.dialogues.exchanges.first().responses.single().status)
        assertTrue(session.dialogues.exchanges[1].matches("netstat-healthy"))
        assertEquals("https://example.test/one", session.dialogues.exchanges[1].request?.target)
    }

    @Test fun failedUpstreamLeavesTheRequestAndAnIncompleteExchange() {
        val session = read("""{"format":"netstat-https","version":1,"client":"Test","host":"example.test","port":443,"flows":[
            {"id":"one","request":{"method":"GET","url":"https://example.test/","version":"HTTP/1.1"}}
            ]}""")
        val call = session.dialogues.exchanges.single()
        assertTrue(call.incomplete)
        assertTrue(call.responses.isEmpty())
        assertEquals("GET", call.request?.method)
    }

    @Test fun rejectsUnsupportedFormatAndOutOfScopeUrls() {
        assertThrows(IOException::class.java) { read("""{"format":"netstat-https","version":2}""") }
        assertThrows(IOException::class.java) { read("""{"format":"netstat-https","version":1,"client":"Test","host":"example.test","port":443,"flows":[
            {"id":"one","request":{"method":"GET","url":"https://other.test/","version":"HTTP/1.1"}}
            ]}""") }
    }

    @Test fun rejectsDeepNestingBeforeCallingTheAndroidJsonParser() {
        assertThrows(IOException::class.java) { read("{\"flows\":" + "[".repeat(30) + "0" + "]".repeat(30) + "}") }
        assertThrows(IOException::class.java) { read("{'flows':[]}") }
    }

    private fun read(value: String) = readHttpsSession(value.byteInputStream())
}
