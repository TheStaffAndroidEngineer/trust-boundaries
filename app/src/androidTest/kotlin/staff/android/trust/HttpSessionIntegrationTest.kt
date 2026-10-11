package staff.android.trust

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.*
import org.junit.Assert.*
import org.junit.rules.TestName
import org.junit.runner.RunWith
import staff.android.trust.session.*

/** Real HttpSessionApi + controller against the owned loopback fixture; no UI sign-in claim. */
@RunWith(AndroidJUnit4::class)
class HttpSessionIntegrationTest {
    @get:Rule val name = TestName()
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val secrets = mutableSetOf<String>()
    private val observations = JSONObject()
    private var completed = false
    private class MemoryStore : SessionStore {
        var value: Tokens? = null
        override suspend fun read() = value
        override suspend fun write(tokens: Tokens) { value = tokens }
        override suspend fun clear() { value = null }
    }
    private inner class TrackedApi : SessionApi {
        private val actual = HttpSessionApi()
        private fun remember(value: Tokens): Tokens {
            secrets += value.accessToken; secrets += value.refreshToken; return value
        }
        override suspend fun exchange(code: String, verifier: String): Tokens {
            secrets += code; secrets += verifier; return remember(actual.exchange(code, verifier))
        }
        override suspend fun refresh(refreshToken: String): Tokens {
            secrets += refreshToken; return remember(actual.refresh(refreshToken))
        }
        override suspend fun revoke(refreshToken: String) = actual.revoke(refreshToken)
        override suspend fun orders(accessToken: String) = actual.orders(accessToken)
        override suspend fun receipt(accessToken: String, id: String) = actual.receipt(accessToken, id)
    }
    private data class Reply(val status: Int, val body: ByteArray, val location: String?) {
        override fun toString() = "Reply(status=$status, body=[redacted], location=[redacted])"
    }
    private fun bounded(input: InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream(); val buffer = ByteArray(4096)
        while (true) {
            val count = input.read(buffer); if (count < 0) break
            check(out.size() + count <= 65_536) { "Test response exceeded bound" }
            out.write(buffer, 0, count)
        }
        return out.toByteArray()
    }
    private suspend fun request(method: String, path: String, body: String? = null,
        form: Boolean = false, access: String? = null): Reply = withContext(Dispatchers.IO) {
        val connection = URI("http://127.0.0.1:8875$path").toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method; connection.connectTimeout = 5_000; connection.readTimeout = 5_000
            connection.instanceFollowRedirects = false; connection.useCaches = false
            if (access != null) connection.setRequestProperty("Authorization", "Bearer $access")
            if (body != null) {
                val bytes = body.toByteArray(StandardCharsets.UTF_8)
                connection.doOutput = true; connection.setFixedLengthStreamingMode(bytes.size)
                connection.setRequestProperty("Content-Type", if (form) "application/x-www-form-urlencoded" else "application/json")
                connection.outputStream.use { it.write(bytes) }
            }
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            Reply(status, stream?.use(::bounded) ?: ByteArray(0), connection.getHeaderField("Location"))
        } finally { connection.disconnect() }
    }
    private suspend fun admin(path: String, body: JSONObject = JSONObject()) {
        assertEquals(200, request("POST", path, body.toString()).status)
    }
    private suspend fun events(): JSONArray {
        val response = request("GET", "/admin/events"); assertEquals(200, response.status)
        return JSONObject(response.body.decodeToString()).getJSONArray("events")
    }
    private fun count(events: JSONArray, kind: String, outcome: String): Int =
        (0 until events.length()).count { events.getJSONObject(it).let { row -> row.getString("kind") == kind && row.getString("outcome") == outcome } }
    private suspend fun signIn(controller: SessionController, account: String = "maya") {
        val url = controller.beginLogin("http://127.0.0.1:8875")
        val pairs = URI(url).rawQuery.split('&').associate { pair ->
            val p = pair.split('=', limit = 2); p[0] to URLDecoder.decode(p[1], "UTF-8")
        }.toMutableMap()
        secrets += pairs.getValue("state"); pairs["account"] = account
        val form = pairs.entries.joinToString("&") { (key, value) -> key + "=" + URLEncoder.encode(value, "UTF-8") }
        val reply = request("POST", "/choose", form, form = true); assertEquals(302, reply.status)
        val callback = reply.location ?: throw AssertionError("Missing fixture callback")
        val fields = EntryPolicy.callbackFields(callback) ?: throw AssertionError("Malformed fixture callback")
        secrets += fields.getValue("code")
        assertTrue(controller.completeLogin(callback)); assertEquals(account, controller.state.value.account?.id)
    }
    private suspend fun awaitAdmission(previous: Int) {
        withTimeout(5_000) {
            while (count(events(), "receipt", "admitted") <= previous) delay(20)
        }
    }

    @Before fun before() = runBlocking<Unit> {
        val app = context.applicationContext as GoodsApplication
        app.ready.await(); app.controller.signOut(); SecureSessionStore(context).clear()
        admin("/admin/reset")
    }
    @After fun after() = runBlocking<Unit> {
        var rows = JSONArray(); var auditOkay = false
        try {
            rows = events()
            val fields = setOf("sequence", "kind", "outcome", "principal", "resource")
            val kinds = setOf("authorize", "choose", "exchange", "refresh", "revoke", "orders", "receipt")
            val outcomes = setOf("rejected", "chooser", "code_issued", "issued", "unauthorized", "unavailable", "allowed",
                "denied", "admitted", "completed", "reuse_family_revoked", "expired", "rotated", "response_dropped", "accepted")
            for (i in 0 until rows.length()) {
                val row = rows.getJSONObject(i)
                check(row.keys().asSequence().all { it in fields })
                check(row.getInt("sequence") == i + 1 && row.getString("kind") in kinds && row.getString("outcome") in outcomes)
                check(!row.has("principal") || row.getString("principal") in setOf("maya", "leo"))
                check(!row.has("resource") || row.getString("resource") in setOf("cg-1042", "cg-2088", "cg-9999"))
            }
            auditOkay = secrets.none { rows.toString().contains(it) }
        } catch (_: Exception) { auditOkay = false }
        val report = JSONObject().put("case", name.methodName).put("completed", completed).put("typed_event_audit_passed", auditOkay)
            .put("known_secret_values_scanned_in_memory", secrets.size).put("observations", observations)
            .put("events", if (auditOkay) rows else JSONArray()).put("scope", "Real HttpSessionApi/controller, test helper chooses sample account; not browser/UI execution")
        check(secrets.none { report.toString().contains(it) }) { "Refusing to persist credential-bearing test report" }
        val directory = File(context.filesDir, "http-integration").apply { mkdirs() }
        File(directory, name.methodName + ".json").writeText(report.toString(2))
        SecureSessionStore(context).clear(); admin("/admin/reset")
        assertTrue("Typed event redaction audit failed", auditOkay)
    }

    @Test fun ownedReceiptForeignReceiptAndGenericMissingAreEnforcedByService() = runBlocking<Unit> {
        val store = MemoryStore(); val c = SessionController(TrackedApi(), store); signIn(c)
        c.loadOrders(); assertEquals(listOf("cg-1042"), c.state.value.orders.map { it.id })
        c.openReceipt("cg-1042"); assertEquals(1_299_900L, c.state.value.receipt?.totalMinor)
        c.openReceipt("cg-2088"); assertNull(c.state.value.receipt); assertEquals(Notice.Unavailable, c.state.value.notice)
        val access = store.value!!.accessToken
        val foreign = request("GET", "/orders/cg-2088", access = access)
        val absent = request("GET", "/orders/cg-9999", access = access)
        assertEquals(404, foreign.status); assertEquals(404, absent.status)
        assertTrue(foreign.body.contentEquals(absent.body)); assertEquals(setOf("error"), JSONObject(foreign.body.decodeToString()).keys().asSequence().toSet())
        observations.put("owned_minor_units", 1_299_900).put("foreign_status", 404).put("missing_status", 404)
            .put("same_generic_error_without_receipt_fields", true)
        completed = true
    }

    @Test fun expiredAccessRotatesOnceAndRetriesTheSameReceipt() = runBlocking<Unit> {
        val store = MemoryStore(); val c = SessionController(TrackedApi(), store); signIn(c)
        val old = store.value!!; admin("/admin/expire-access"); c.openReceipt("cg-1042")
        assertEquals("cg-1042", c.state.value.receipt?.id)
        assertTrue(old.accessToken != store.value!!.accessToken); assertTrue(old.refreshToken != store.value!!.refreshToken)
        val rows = events(); assertEquals(1, count(rows, "receipt", "unauthorized")); assertEquals(1, count(rows, "refresh", "rotated"))
        assertEquals(1, count(rows, "receipt", "completed"))
        observations.put("resource_401", 1).put("rotations", 1).put("completed_receipts", 1)
        completed = true
    }

    @Test fun droppedRefreshResponseEndsLocalAuthorityAndRecordsActualTransportAttempts() = runBlocking<Unit> {
        val store = MemoryStore(); val c = SessionController(TrackedApi(), store); signIn(c)
        admin("/admin/expire-access"); admin("/admin/config", JSONObject().put("drop_refresh_response", true))
        c.loadOrders(); assertNull(store.value); assertNull(c.state.value.account); assertEquals(Notice.SessionEnded, c.state.value.notice)
        val rows = events(); val rotations = count(rows, "refresh", "rotated"); val dropped = count(rows, "refresh", "response_dropped")
        val replay = count(rows, "refresh", "reuse_family_revoked")
        assertEquals(1, rotations); assertEquals(1, dropped)
        val attempts = (0 until rows.length()).count { rows.getJSONObject(it).let { r ->
            r.getString("kind") == "refresh" && r.getString("outcome") in setOf("rotated", "reuse_family_revoked", "expired", "rejected") } }
        assertTrue(attempts >= 1)
        c.loadOrders(); assertEquals(rows.length(), events().length()); assertEquals(Notice.SignInRequired, c.state.value.notice)
        observations.put("rotations", rotations).put("dropped_responses", dropped).put("refresh_http_attempts", attempts)
            .put("reuse_events", replay).put("next_unsigned_load_issued_no_http", true)
        completed = true
    }

    @Test fun admittedReceiptCompletingAfterLogoutCannotRepopulateState() = runBlocking<Unit> {
        val c = SessionController(TrackedApi(), MemoryStore()); signIn(c)
        admin("/admin/config", JSONObject().put("receipt_delay_ms", 1_500))
        val previous = count(events(), "receipt", "admitted")
        val request = async { c.openReceipt("cg-1042") }; awaitAdmission(previous)
        c.signOut(); assertNull(c.state.value.account); request.await()
        assertNull(c.state.value.account); assertNull(c.state.value.receipt); assertEquals(Notice.SignedOut, c.state.value.notice)
        val rows = events(); assertEquals(1, count(rows, "receipt", "completed")); assertEquals(1, count(rows, "revoke", "accepted"))
        observations.put("admitted_before_transition", true).put("completed_after_local_logout", true).put("old_receipt_published", false)
        completed = true
    }

    @Test fun admittedMayaReceiptCannotPublishAfterLeoBecomesCurrent() = runBlocking<Unit> {
        val store = MemoryStore(); val c = SessionController(TrackedApi(), store); signIn(c)
        admin("/admin/config", JSONObject().put("receipt_delay_ms", 1_500))
        val previous = count(events(), "receipt", "admitted")
        val request = async { c.openReceipt("cg-1042") }; awaitAdmission(previous)
        signIn(c, "leo"); c.loadOrders(); val leoState = c.state.value; request.await()
        assertEquals(leoState, c.state.value); assertEquals("leo", store.value?.account?.id)
        assertEquals(listOf("cg-2088"), c.state.value.orders.map { it.id }); assertNull(c.state.value.receipt)
        observations.put("admitted_account", "maya").put("current_account", "leo").put("current_order_ids", JSONArray().put("cg-2088"))
            .put("old_receipt_published", false)
        completed = true
    }

    @Test fun encryptedSessionRestoresIntoFreshControllerAndLogoutRemovesIt() = runBlocking<Unit> {
        val first = SessionController(TrackedApi(), SecureSessionStore(context)); signIn(first)
        val second = SessionController(TrackedApi(), SecureSessionStore(context)); second.restore(); second.loadOrders()
        assertEquals("maya", second.state.value.account?.id); assertEquals(listOf("cg-1042"), second.state.value.orders.map { it.id })
        assertEquals(1, count(events(), "exchange", "issued")); second.signOut()
        val third = SessionController(TrackedApi(), SecureSessionStore(context)); third.restore()
        assertNull(third.state.value.account); assertNull(SecureSessionStore(context).read())
        observations.put("fresh_controller_restored", true).put("code_exchanges", 1).put("after_logout_restoration_signed_out", true)
        completed = true
    }
}
