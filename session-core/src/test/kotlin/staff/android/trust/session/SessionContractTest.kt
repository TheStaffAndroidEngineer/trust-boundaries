package staff.android.trust.session

import java.io.IOException
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class SessionContractTest {
    private val maya = Account("maya", "Maya")
    private val leo = Account("leo", "Leo")
    private fun tokens(account: Account = maya, marker: Char = 'A', expiry: Long = 10_000L) =
        Tokens(account, marker.toString().repeat(43), marker.lowercaseChar().toString().repeat(43), expiry)
    private fun receipt(id: String = "cg-1042", owner: String = "maya") =
        Receipt(id, owner, "camera", "Camera", 1_299_900, "Delivered")

    private class Store(var value: Tokens? = null) : SessionStore {
        var reads = 0
        var writes = 0
        var clears = 0
        var onWrite: suspend (Tokens) -> Unit = {}
        var onClear: suspend () -> Unit = {}
        override suspend fun read(): Tokens? { reads++; return value }
        override suspend fun write(tokens: Tokens) { writes++; onWrite(tokens); value = tokens }
        override suspend fun clear() { clears++; onClear(); value = null }
    }
    private class Api : SessionApi {
        val exchanges = mutableListOf<Pair<String, String>>()
        val refreshes = mutableListOf<String>()
        val revocations = mutableListOf<String>()
        val receiptCalls = mutableListOf<Pair<String, String>>()
        val orderCalls = mutableListOf<String>()
        var exchangeBlock: suspend (String, String) -> Tokens = { _, _ -> error("Unexpected exchange") }
        var refreshBlock: suspend (String) -> Tokens = { error("Unexpected refresh") }
        var revokeBlock: suspend (String) -> Unit = {}
        var receiptBlock: suspend (String, String) -> Receipt = { _, _ -> error("Unexpected receipt") }
        var ordersBlock: suspend (String) -> List<OrderSummary> = { emptyList() }
        override suspend fun exchange(code: String, verifier: String): Tokens {
            exchanges += code to verifier; return exchangeBlock(code, verifier)
        }
        override suspend fun refresh(refreshToken: String): Tokens {
            refreshes += refreshToken; return refreshBlock(refreshToken)
        }
        override suspend fun revoke(refreshToken: String) { revocations += refreshToken; revokeBlock(refreshToken) }
        override suspend fun receipt(accessToken: String, id: String): Receipt {
            receiptCalls += accessToken to id; return receiptBlock(accessToken, id)
        }
        override suspend fun orders(accessToken: String): List<OrderSummary> {
            orderCalls += accessToken; return ordersBlock(accessToken)
        }
    }
    private class Clock(var now: Long = 1_000L)
    private fun controller(api: Api, store: Store, clock: Clock = Clock()): SessionController {
        var secret = 0
        return SessionController(api, store, { clock.now }, { ('B'.code + secret++).toChar().toString().repeat(43) })
    }
    private fun parameters(url: String) = URI(url).rawQuery.split('&').associate { pair ->
        val parts = pair.split('=', limit = 2)
        parts[0] to URLDecoder.decode(parts[1], StandardCharsets.UTF_8)
    }
    private suspend fun begin(c: SessionController): String = parameters(c.beginLogin("http://127.0.0.1:8875")).getValue("state")
    private fun callback(state: String, code: String = "K".repeat(43)) = "${EntryPolicy.callback}?code=$code&state=$state"
    private suspend inline fun <reified T : Throwable> expectFailure(crossinline block: suspend () -> Unit): T {
        try { block() } catch (failure: Throwable) {
            assertTrue(failure is T, "Expected ${T::class.simpleName}, got ${failure::class.simpleName}")
            return failure as T
        }
        throw AssertionError("Expected ${T::class.simpleName}")
    }

    @Test fun receiptLocatorAcceptsOnlyTheDeclaredLanguage() {
        assertEquals("cg-1042", EntryPolicy.receiptId("https://commongoods.example/orders/cg-1042"))
        listOf("http://commongoods.example/orders/cg-1042", "https://commongoods.example.evil/orders/cg-1042",
            "https://commongoods.example@evil.example/orders/cg-1042", "https://commongoods.example:443/orders/cg-1042",
            "https://COMMONGOODS.example/orders/cg-1042", "https://commongoods.example/orders/%63g-1042",
            "https://commongoods.example/orders/cg-1042?account=leo", "https://commongoods.example/orders/cg-1042#x",
            "https://commongoods.example/orders/cg-1042/", "https://commongoods.example/orders/../orders/cg-1042",
            " https://commongoods.example/orders/cg-1042", "https://commongoods.example/orders/cg-1042\n",
            "https://commongoods.example/orders/cg-10420").forEach { assertNull(EntryPolicy.receiptId(it), it) }
    }

    @Test fun callbackRejectsDuplicateExtraEncodedAndWrongEndpointInputs() {
        val state = "S".repeat(43); val code = "C".repeat(43)
        assertEquals(mapOf("state" to state, "code" to code), EntryPolicy.callbackFields("${EntryPolicy.callback}?state=$state&code=$code"))
        listOf("${EntryPolicy.callback}?state=$state&state=$state", "${EntryPolicy.callback}?state=$state&code=$code&account=maya",
            "${EntryPolicy.callback}?state=$state&code=%43$code", "${EntryPolicy.callback}?state=$state&code=$code#fragment",
            "staff.android.trust://evil/oauth2redirect?state=$state&code=$code",
            "staff.android.trust:/oauth2redirect/?state=$state&code=$code",
            "STAFF.android.trust:/oauth2redirect?state=$state&code=$code",
            "${EntryPolicy.callback}?state=$state&code=short", "${EntryPolicy.callback}?state=$state&code=$code=",
            "${EntryPolicy.callback}?state=${"S".repeat(2050)}&code=$code").forEach { assertNull(EntryPolicy.callbackFields(it), it) }
    }

    @Test fun pkceMatchesPublishedRfc7636VectorAndDoesNotExposeVerifier() = runTest {
        // RFC7636 Appendix B deterministic interoperability vector, not a production secret.
        val attempt = LoginAttempt("S".repeat(43), "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", 1, 0)
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", attempt.challenge)
        val c = controller(Api(), Store()); val first = c.beginLogin("http://127.0.0.1:8875")
        val values = parameters(first)
        assertEquals(EntryPolicy.callback, values["redirect_uri"]); assertEquals("S256", values["code_challenge_method"])
        assertEquals("code", values["response_type"]); assertEquals(EntryPolicy.clientId, values["client_id"])
        assertFalse(first.contains("C".repeat(43))); assertFalse(first.contains("client_secret"))
        assertNotEquals(values["state"], parameters(c.beginLogin("http://127.0.0.1:8875"))["state"])
        assertFalse(attempt.toString().contains(attempt.verifier)); assertFalse(tokens().toString().contains(tokens().accessToken))
    }

    @Test fun wrongStateDoesNotSpendCorrectPendingAttemptAndReplayCannotExchangeTwice() = runTest {
        val api = Api().apply { exchangeBlock = { _, _ -> tokens() } }; val store = Store(); val c = controller(api, store)
        val state = begin(c)
        assertFalse(c.completeLogin(callback("Z".repeat(43)))); assertEquals(0, api.exchanges.size)
        assertTrue(c.completeLogin(callback(state))); assertEquals(maya, c.state.value.account)
        assertFalse(c.completeLogin(callback(state))); assertEquals(1, api.exchanges.size); assertEquals(1, store.writes)
        assertEquals("C".repeat(43), api.exchanges.single().second)
    }

    @Test fun expiryBoundaryAndClockRollbackRejectAndConsumeTheMatchingAttempt() = runTest {
        for (change in listOf(300_000L, -1L)) {
            val clock = Clock(); val api = Api(); val c = controller(api, Store(), clock); val state = begin(c)
            clock.now += change
            assertFalse(c.completeLogin(callback(state))); assertEquals(Notice.SignInFailed, c.state.value.notice)
            clock.now = 1_000L
            assertFalse(c.completeLogin(callback(state))); assertTrue(api.exchanges.isEmpty())
        }
    }

    @Test fun newAttemptSupersedesOlderCallbackEvenForSameAccount() = runTest {
        val api = Api().apply { exchangeBlock = { _, _ -> tokens() } }; val c = controller(api, Store())
        val old = begin(c); val current = begin(c)
        assertFalse(c.completeLogin(callback(old))); assertTrue(c.completeLogin(callback(current)))
        assertEquals(1, api.exchanges.size)
    }

    @Test fun failedExchangeCannotReuseItsConsumedAttempt() = runTest {
        val api = Api().apply { exchangeBlock = { _, _ -> throw IOException("transport lost") } }
        val store = Store(); val c = controller(api, store); val state = begin(c)
        assertFalse(c.completeLogin(callback(state))); assertFalse(c.completeLogin(callback(state)))
        assertEquals(1, api.exchanges.size); assertNull(store.value); assertFalse(c.state.value.loading)
    }

    @Test fun logoutFencesAnAlreadyStartedSuccessfulCodeExchange() = runTest {
        val response = CompletableDeferred<Tokens>(); val api = Api().apply { exchangeBlock = { _, _ -> response.await() } }
        val store = Store(); val c = controller(api, store); val state = begin(c)
        val login = async { c.completeLogin(callback(state)) }; runCurrent(); assertEquals(1, api.exchanges.size)
        c.signOut(); response.complete(tokens()); assertFalse(login.await())
        assertNull(c.state.value.account); assertNull(store.value); assertEquals(0, store.writes)
    }

    @Test fun cancelLoginRejectsBothPendingCallbackAndAlreadyRunningExchange() = runTest {
        val response = CompletableDeferred<Tokens>(); val api = Api().apply { exchangeBlock = { _, _ -> response.await() } }
        val store = Store(); val c = controller(api, store)
        val abandoned = begin(c); c.cancelLogin()
        assertFalse(c.completeLogin(callback(abandoned))); assertTrue(api.exchanges.isEmpty())
        assertFalse(c.state.value.loading); assertEquals(Notice.SignInRequired, c.state.value.notice)
        val current = begin(c); val exchange = async { c.completeLogin(callback(current)) }; runCurrent()
        assertEquals(1, api.exchanges.size); c.cancelLogin(); response.complete(tokens())
        assertFalse(exchange.await()); assertNull(store.value); assertEquals(0, store.writes)
        assertEquals(Notice.SignInRequired, c.state.value.notice)
    }

    @Test fun cancelLoginDoesNotSignOutAnEstablishedSession() = runTest {
        val api = Api().apply { receiptBlock = { _, _ -> receipt() } }; val store = Store(tokens())
        val c = controller(api, store); c.restore(); c.openReceipt("cg-1042"); val before = c.state.value
        c.cancelLogin()
        assertEquals(before, c.state.value); assertEquals(tokens(), store.value); assertEquals(0, store.clears)
    }

    @Test fun corruptRestorationAndUnsignedReceiptNeverCallTheService() = runTest {
        val api = Api(); val store = Store(tokens().copy(accessToken = "bad")); val c = controller(api, store)
        c.restore(); c.openReceipt("cg-1042")
        assertNull(c.state.value.account); assertEquals(Notice.SignInRequired, c.state.value.notice)
        assertTrue(api.receiptCalls.isEmpty()); assertEquals("cg-1042", c.state.value.requestedId)
    }

    @Test fun restorationCannotReintroduceSessionAfterSignout() = runTest {
        val store = Store(tokens()); val c = controller(Api(), store); c.restore(); assertEquals(maya, c.state.value.account)
        c.signOut(); store.value = tokens(); c.restore()
        assertNull(c.state.value.account); assertEquals(1, store.reads)
    }

    @Test fun lateReceiptCannotPublishAfterLogoutOrSameAccountReauthentication() = runTest {
        val late = CompletableDeferred<Receipt>(); val api = Api().apply {
            receiptBlock = { _, _ -> late.await() }; exchangeBlock = { _, _ -> tokens(marker = 'B') }
        }
        val store = Store(tokens()); val c = controller(api, store); c.restore()
        val fetch = launch { c.openReceipt("cg-1042") }; runCurrent(); assertEquals(1, api.receiptCalls.size)
        c.signOut(); val state = begin(c); assertTrue(c.completeLogin(callback(state)))
        late.complete(receipt()); fetch.join()
        assertEquals(maya, c.state.value.account); assertNull(c.state.value.receipt)
        assertEquals('B'.toString().repeat(43), store.value?.accessToken)
    }

    @Test fun accountChangeFencesReceiptAndKeepsNewAccountContext() = runTest {
        val late = CompletableDeferred<Receipt>(); val api = Api().apply {
            receiptBlock = { _, _ -> late.await() }; exchangeBlock = { _, _ -> tokens(leo, 'L') }
        }
        val c = controller(api, Store(tokens())); c.restore()
        val fetch = launch { c.openReceipt("cg-1042") }; runCurrent()
        assertTrue(c.completeLogin(callback(begin(c)))); late.complete(receipt()); fetch.join()
        assertEquals(leo, c.state.value.account); assertNull(c.state.value.receipt)
    }

    @Test fun newerRequestWinsAndDeniedRequestDoesNotLeaveOldReceiptVisible() = runTest {
        val old = CompletableDeferred<Receipt>(); val api = Api().apply {
            receiptBlock = { _, id -> if (id == "cg-1042") old.await() else throw ServiceFailure(403) }
        }
        val c = controller(api, Store(tokens())); c.restore()
        val fetch = launch { c.openReceipt("cg-1042") }; runCurrent(); c.openReceipt("cg-2088")
        old.complete(receipt()); fetch.join()
        assertNull(c.state.value.receipt); assertEquals("cg-2088", c.state.value.requestedId)
        assertEquals(Notice.Unavailable, c.state.value.notice); assertEquals(maya, c.state.value.account)
    }

    @Test fun ownerMismatchInSuccessfulResponseIsNotPublished() = runTest {
        val api = Api().apply { receiptBlock = { _, _ -> receipt(owner = "leo") } }
        val c = controller(api, Store(tokens())); c.restore(); c.openReceipt("cg-1042")
        assertNull(c.state.value.receipt); assertEquals(Notice.Retry, c.state.value.notice)
    }

    @Test fun overlappingExpiredRequestsRotateOnceAndUseThePublishedReplacement() = runTest {
        val replacement = tokens(marker = 'B'); val rotation = CompletableDeferred<Tokens>()
        val api = Api().apply { refreshBlock = { rotation.await() }; receiptBlock = { _, id -> receipt(id) } }
        val store = Store(tokens(expiry = 1_000L)); val c = controller(api, store); c.restore()
        val first = launch { c.openReceipt("cg-1042") }; runCurrent()
        val second = launch { c.loadOrders() }; runCurrent(); assertEquals(1, api.refreshes.size)
        rotation.complete(replacement); first.join(); second.join()
        assertEquals(1, api.refreshes.size); assertEquals(1, store.writes); assertEquals(replacement, store.value)
        assertEquals(listOf(replacement.accessToken), api.orderCalls)
        assertEquals(replacement.accessToken, api.receiptCalls.single().first); assertNull(c.state.value.receipt)
    }

    @Test fun unauthorizedResponseRefreshesThenRepeatsTheSameResourceOnce() = runTest {
        val replacement = tokens(marker = 'B'); val api = Api().apply {
            refreshBlock = { replacement }
            receiptBlock = { access, id -> if (access == tokens().accessToken) throw ServiceFailure(401) else receipt(id) }
        }
        val c = controller(api, Store(tokens())); c.restore(); c.openReceipt("cg-1042")
        assertEquals(listOf(tokens().accessToken to "cg-1042", replacement.accessToken to "cg-1042"), api.receiptCalls)
        assertEquals(1, api.refreshes.size); assertEquals("cg-1042", c.state.value.receipt?.id)
    }

    @Test fun repeatedUnauthorizedResponseEndsSessionWithoutRefreshLoop() = runTest {
        val api = Api().apply { refreshBlock = { tokens(marker = 'B') }; receiptBlock = { _, _ -> throw ServiceFailure(401) } }
        val store = Store(tokens()); val c = controller(api, store); c.restore(); c.openReceipt("cg-1042")
        assertEquals(1, api.refreshes.size); assertEquals(2, api.receiptCalls.size)
        assertNull(store.value); assertNull(c.state.value.account); assertEquals(Notice.SessionEnded, c.state.value.notice)
    }

    @Test fun failedOrAmbiguousRefreshRequiresNewSignInAndCannotRetryConsumedSecret() = runTest {
        for (failure in listOf(IOException("response lost"), ServiceFailure(400))) {
            val api = Api().apply { refreshBlock = { throw failure } }
            val store = Store(tokens(expiry = 999)); val c = controller(api, store); c.restore()
            c.openReceipt("cg-1042"); c.openReceipt("cg-1042")
            assertEquals(1, api.refreshes.size); assertNull(store.value); assertNull(c.state.value.account)
            assertEquals(Notice.SignInRequired, c.state.value.notice); assertTrue(api.receiptCalls.isEmpty())
        }
    }

    @Test fun cancelledRefreshClearsAmbiguousAuthorityBeforePropagatingCancellation() = runTest {
        val never = CompletableDeferred<Tokens>(); val api = Api().apply { refreshBlock = { never.await() } }
        val store = Store(tokens(expiry = 999)); val c = controller(api, store); c.restore()
        val fetch = launch { c.openReceipt("cg-1042") }; runCurrent(); assertEquals(1, api.refreshes.size)
        fetch.cancelAndJoin()
        assertNull(c.state.value.account); assertNull(store.value)
        c.openReceipt("cg-1042"); assertEquals(1, api.refreshes.size)
    }

    @Test fun cancellationDuringLoginWriteDoesNotLeaveRestorablePartialSession() = runTest {
        val never = CompletableDeferred<Unit>(); val store = Store()
        store.onWrite = { value -> store.value = value; never.await() }
        val api = Api().apply { exchangeBlock = { _, _ -> tokens() } }; val c = controller(api, store)
        val state = begin(c); val login = launch { c.completeLogin(callback(state)) }; runCurrent()
        assertEquals(1, store.writes); login.cancelAndJoin()
        assertNull(c.state.value.account); assertNull(store.value); assertFalse(c.state.value.loading)
    }

    @Test fun lateRefreshCannotOverwriteNewAccountOrItsPersistedTokens() = runTest {
        val late = CompletableDeferred<Tokens>(); val leoTokens = tokens(leo, 'L')
        val api = Api().apply { refreshBlock = { late.await() }; exchangeBlock = { _, _ -> leoTokens } }
        val store = Store(tokens(expiry = 999)); val c = controller(api, store); c.restore()
        val fetch = launch { c.openReceipt("cg-1042") }; runCurrent()
        assertTrue(c.completeLogin(callback(begin(c)))); late.complete(tokens(marker = 'B')); fetch.join()
        assertEquals(leoTokens, store.value); assertEquals(leo, c.state.value.account); assertTrue(api.receiptCalls.isEmpty())
    }

    @Test fun storageFailurePreventsLoginPublicationAndClearsPartialWrite() = runTest {
        val store = Store(); store.onWrite = { value -> store.value = value; throw IOException("commit status unknown") }
        val api = Api().apply { exchangeBlock = { _, _ -> tokens() } }; val c = controller(api, store)
        assertFalse(c.completeLogin(callback(begin(c)))); assertNull(c.state.value.account); assertNull(store.value)
        assertEquals(Notice.SignInFailed, c.state.value.notice)
    }

    @Test fun cancellationDuringFailureCleanupCannotLeavePartialLoginOnDisk() = runTest {
        val cleanup = CompletableDeferred<Unit>(); val store = Store()
        store.onWrite = { value -> store.value = value; throw IOException("commit status unknown") }
        store.onClear = { if (store.clears == 2) cleanup.await() }
        val api = Api().apply { exchangeBlock = { _, _ -> tokens() } }; val c = controller(api, store)
        val state = begin(c); val login = launch { c.completeLogin(callback(state)) }; runCurrent()
        assertEquals(2, store.clears); assertNotNull(store.value)
        login.cancel(); runCurrent()
        assertFalse(login.isCompleted, "Local cleanup must finish even when its original caller is cancelled")
        cleanup.complete(Unit); login.join()
        assertNull(store.value); assertNull(c.state.value.account); assertFalse(c.state.value.loading)
    }

    @Test fun signoutClearsVisibleStateEvenWhenStorageClearFailsAndRetriesOldRevocation() = runTest {
        val api = Api(); val original = tokens(); val store = Store(original); val c = controller(api, store); c.restore()
        store.onClear = { throw IOException("disk unavailable") }; c.signOut()
        assertNull(c.state.value.account); assertNull(c.state.value.receipt); assertEquals(Notice.LocalSignOutFailed, c.state.value.notice)
        assertTrue(api.revocations.isEmpty()); assertEquals(original, store.value)
        c.cancelLogin(); assertEquals(Notice.LocalSignOutFailed, c.state.value.notice)
        store.onClear = {}; c.signOut()
        assertNull(store.value); assertEquals(listOf(original.refreshToken), api.revocations)
        assertEquals(Notice.SignedOut, c.state.value.notice)
    }

    @Test fun remoteRevocationFailureDoesNotUndoLocalLogoutAndCanBeRetried() = runTest {
        val original = tokens(); val api = Api().apply { revokeBlock = { throw IOException("offline") } }
        val store = Store(original); val c = controller(api, store); c.restore(); c.signOut()
        assertNull(store.value); assertNull(c.state.value.account); assertEquals(Notice.RemoteSignOutUnconfirmed, c.state.value.notice)
        api.revokeBlock = {}; c.signOut()
        assertEquals(listOf(original.refreshToken, original.refreshToken), api.revocations)
        assertEquals(Notice.SignedOut, c.state.value.notice)
    }
    @Test fun activityFailureAdaptersPreserveTheSessionFailureAndLocalCleanupNotice() = runTest {
        val api = Api().apply { exchangeBlock = { _, _ -> throw IOException("exchange unavailable") } }
        val store = Store(); val c = controller(api, store)
        assertFalse(c.completeLogin(callback(begin(c))))
        assertEquals(Notice.SignInFailed, c.state.value.notice)
        c.rejectLink(preserveExistingNotice = true)
        assertEquals(Notice.SignInFailed, c.state.value.notice)

        store.onClear = { throw IOException("credential cleanup unavailable") }
        expectFailure<IOException> { c.beginLogin("http://127.0.0.1:8875") }
        assertEquals(Notice.LocalSignOutFailed, c.state.value.notice)
        c.cancelLogin() // Activity launch adapter's failure path.
        c.rejectLink(preserveExistingNotice = true)
        assertEquals(Notice.LocalSignOutFailed, c.state.value.notice)
        assertFalse(c.state.value.loading); assertNull(c.state.value.account)
    }

    @Test fun rejectedCallbackAddsNoticeWithoutSpendingExpectedAttemptAndLaunchCancellationSpendsIt() = runTest {
        val api = Api().apply { exchangeBlock = { _, _ -> tokens() } }
        val c = controller(api, Store()); val state = begin(c)
        assertFalse(c.completeLogin(callback("Z".repeat(43))))
        c.rejectLink(preserveExistingNotice = true)
        assertEquals(Notice.InvalidLink, c.state.value.notice)
        assertTrue(c.completeLogin(callback(state))); assertEquals(1, api.exchanges.size)

        val abandoned = begin(c)
        c.cancelLogin() // Failed external browser launch abandons this new attempt.
        assertFalse(c.completeLogin(callback(abandoned)))
        assertEquals(1, api.exchanges.size); assertEquals(Notice.SignInRequired, c.state.value.notice)
        assertNull(c.state.value.account)
    }
}
