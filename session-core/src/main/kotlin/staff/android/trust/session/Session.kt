package staff.android.trust.session

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.IOException
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

@Serializable data class Account(val id: String, val name: String)
@Serializable data class Tokens(val account: Account, val accessToken: String, val refreshToken: String, val expiresAtMillis: Long) {
    override fun toString() = "Tokens([redacted])"
}
@Serializable data class OrderSummary(val id: String, val productId: String, val title: String, val totalMinor: Long)
@Serializable data class Receipt(val id: String, val ownerId: String, val productId: String, val title: String, val totalMinor: Long, val status: String)
enum class Notice { SignInRequired, InvalidLink, SignInFailed, Unavailable, Retry, SessionEnded, SignedOut, LocalSignOutFailed, RemoteSignOutUnconfirmed }
data class OrdersState(val account: Account? = null, val orders: List<OrderSummary> = emptyList(),
    val receipt: Receipt? = null, val requestedId: String? = null, val loading: Boolean = false, val notice: Notice? = null)
interface SessionStore { suspend fun read(): Tokens?; suspend fun write(tokens: Tokens); suspend fun clear() }
interface SessionApi {
    suspend fun exchange(code: String, verifier: String): Tokens
    suspend fun refresh(refreshToken: String): Tokens
    suspend fun revoke(refreshToken: String)
    suspend fun orders(accessToken: String): List<OrderSummary>
    suspend fun receipt(accessToken: String, id: String): Receipt
}
class ServiceFailure(val status: Int) : IOException("Service status $status")
class InvalidSession : IOException("Session is no longer available")

object SessionCodec {
    val json = Json { ignoreUnknownKeys = true }
    fun validate(value: Tokens): Tokens {
        require(value.account.id.matches(Regex("[a-z0-9_-]{1,64}")))
        require(value.account.name.length in 1..60 && value.account.name.none { it.isISOControl() })
        require(listOf(value.accessToken, value.refreshToken).all { it.matches(Regex("[A-Za-z0-9_-]{32,256}")) })
        require(value.expiresAtMillis >= 0)
        return value
    }
}

object EntryPolicy {
    const val clientId = "common-goods-book"
    const val callback = "staff.android.trust:/oauth2redirect"
    private val receiptPattern = Regex("https://commongoods\\.example/orders/(cg-[0-9]{4})")
    fun receiptId(raw: String): String? = if (raw.length <= 256) receiptPattern.matchEntire(raw)?.groupValues?.get(1) else null
    fun validId(id: String) = id.matches(Regex("cg-[0-9]{4}"))
    fun callbackFields(raw: String): Map<String, String>? {
        if (raw.length > 2048) return null
        val uri = runCatching { URI(raw) }.getOrNull() ?: return null
        if (uri.scheme != "staff.android.trust" || uri.rawAuthority != null || uri.rawPath != "/oauth2redirect" || uri.rawFragment != null) return null
        val pairs = uri.rawQuery?.split('&') ?: return null
        if (pairs.size != 2) return null
        val result = linkedMapOf<String, String>()
        for (pair in pairs) {
            val parts = pair.split('=', limit = 2)
            if (parts.size != 2 || parts[0] !in setOf("code", "state") || result.containsKey(parts[0])) return null
            if (!parts[1].matches(Regex("[A-Za-z0-9_-]{32,128}"))) return null
            result[parts[0]] = parts[1]
        }
        return result.takeIf { it.keys == setOf("code", "state") }
    }
}

class LoginAttempt(val state: String, val verifier: String, val generation: Long, val createdAtMillis: Long) {
    val challenge: String get() = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(StandardCharsets.US_ASCII)))
    override fun toString() = "LoginAttempt([redacted])"
}

/** Process-owned session authority. The UI never receives bearer or refresh tokens. */
class SessionController(private val api: SessionApi, private val store: SessionStore,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val randomSecret: () -> String = { ByteArray(32).also(SecureRandom()::nextBytes).let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) } }) {
    private val guard = Mutex()
    private val refreshGuard = Mutex()
    private var generation = 0L
    private var request = 0L
    private var tokens: Tokens? = null
    private var pending: LoginAttempt? = null
    private var revocationPending: String? = null
    private val mutable = MutableStateFlow(OrdersState())
    val state: StateFlow<OrdersState> = mutable.asStateFlow()

    suspend fun restore() = guard.withLock {
        if (generation != 0L || tokens != null) return@withLock
        tokens = try { store.read()?.let(SessionCodec::validate) }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { null }
        mutable.value = OrdersState(account = tokens?.account)
    }

    suspend fun beginLogin(baseUrl: String): String = guard.withLock {
        generation = Math.incrementExact(generation); request = Math.incrementExact(request)
        tokens = null; pending = null
        mutable.value = OrdersState(requestedId = mutable.value.requestedId, loading = true)
        try { withContext(NonCancellable) { store.clear() } } catch (failure: Exception) {
            mutable.value = mutable.value.copy(loading = false, notice = Notice.LocalSignOutFailed)
            throw failure
        }
        val attempt = LoginAttempt(randomSecret(), randomSecret(), generation, nowMillis())
        require(attempt.state.matches(Regex("[A-Za-z0-9_-]{43}")) && attempt.verifier.matches(Regex("[A-Za-z0-9_-]{43}")))
        pending = attempt
        val values = linkedMapOf("client_id" to EntryPolicy.clientId, "redirect_uri" to EntryPolicy.callback,
            "response_type" to "code", "code_challenge_method" to "S256", "code_challenge" to attempt.challenge, "state" to attempt.state)
        baseUrl + "/authorize?" + values.entries.joinToString("&") { (key, value) -> key + "=" + URLEncoder.encode(value, "UTF-8") }
    }

    suspend fun completeLogin(raw: String): Boolean {
        val fields = EntryPolicy.callbackFields(raw) ?: return false
        val attempt = guard.withLock {
            val current = pending ?: return false
            if (!MessageDigest.isEqual(current.state.toByteArray(), fields.getValue("state").toByteArray())) return false
            pending = null // Consume the matching attempt before exchanging its code.
            if (current.generation != generation || nowMillis() < current.createdAtMillis || nowMillis() - current.createdAtMillis >= 300_000) {
                mutable.value = OrdersState(notice = Notice.SignInFailed); return false
            }
            current
        }
        return try {
            val received = SessionCodec.validate(api.exchange(fields.getValue("code"), attempt.verifier))
            guard.withLock {
                if (generation != attempt.generation) return false
                store.write(received)
                tokens = received
                mutable.value = OrdersState(account = received.account, requestedId = mutable.value.requestedId)
                true
            }
        } catch (cancelled: CancellationException) {
            withContext(NonCancellable) { endSession(attempt.generation) }
            throw cancelled
        }
        catch (_: Exception) {
            withContext(NonCancellable) { guard.withLock {
                if (generation == attempt.generation) {
                    tokens = null
                    val cleared = try { store.clear(); true } catch (cancelled: CancellationException) { throw cancelled } catch (_: Exception) { false }
                    mutable.value = OrdersState(notice = if (cleared) Notice.SignInFailed else Notice.LocalSignOutFailed)
                }
            } }
            false
        }
    }

    suspend fun rejectLink(preserveExistingNotice: Boolean = false) = guard.withLock {
        if (!preserveExistingNotice || mutable.value.notice == null)
            mutable.value = mutable.value.copy(notice = Notice.InvalidLink)
    }
    suspend fun cancelLogin() = guard.withLock {
        if (tokens != null || (pending == null && !mutable.value.loading)) return@withLock
        generation = Math.incrementExact(generation); pending = null
        mutable.value = OrdersState(requestedId = mutable.value.requestedId, notice = Notice.SignInRequired)
    }
    suspend fun loadOrders() = load(null)
    suspend fun openReceipt(id: String) {
        if (!EntryPolicy.validId(id)) { rejectLink(); return }
        load(id)
    }
    private suspend fun load(id: String?) {
        val ticket = guard.withLock {
            request = Math.incrementExact(request)
            mutable.value = OrdersState(account = tokens?.account, requestedId = id, loading = tokens != null,
                notice = if (tokens == null) Notice.SignInRequired else null)
            val active = tokens ?: return
            Triple(generation, request, active)
        }
        try {
            var active = ticket.third
            if (nowMillis() >= active.expiresAtMillis) active = refreshed(ticket.first, active)
            suspend fun fetch(current: Tokens): Pair<List<OrderSummary>, Receipt?> =
                if (id == null) api.orders(current.accessToken) to null else emptyList<OrderSummary>() to api.receipt(current.accessToken, id)
            val result = try { fetch(active) } catch (failure: ServiceFailure) {
                if (failure.status != 401) throw failure
                active = refreshed(ticket.first, active); fetch(active)
            }
            val products = setOf("camera", "tea", "bag", "lamp", "mug", "headphones")
            fun validText(text: String, limit: Int) = text.length in 1..limit && text.none { it.isISOControl() }
            require(result.first.size <= 20 && result.first.map { it.id }.distinct().size == result.first.size && result.first.all {
                EntryPolicy.validId(it.id) && it.totalMinor in 0..100_000_000L && it.productId in products && validText(it.title, 80)
            })
            result.second?.let { require(it.id == id && it.ownerId == active.account.id && it.totalMinor in 0..100_000_000L && it.productId in products && validText(it.title, 80) && validText(it.status, 40)) }
            guard.withLock {
                if (generation == ticket.first && request == ticket.second && tokens?.account == active.account)
                    mutable.value = OrdersState(active.account, result.first.toList(), result.second, id)
            }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (failure: Exception) {
            if (failure is ServiceFailure && failure.status == 401) endSession(ticket.first)
            guard.withLock {
                if (generation == ticket.first && request == ticket.second)
                    mutable.value = OrdersState(tokens?.account, requestedId = id,
                        notice = if (failure is ServiceFailure && failure.status in setOf(403, 404)) Notice.Unavailable else Notice.Retry)
            }
        }
    }

    private suspend fun refreshed(expectedGeneration: Long, previous: Tokens): Tokens = refreshGuard.withLock {
        val current = guard.withLock {
            if (generation != expectedGeneration) throw InvalidSession()
            val current = tokens ?: throw InvalidSession()
            if (current.accessToken != previous.accessToken) return current
            current
        }
        try {
            val replacement = SessionCodec.validate(api.refresh(current.refreshToken))
            require(replacement.account == current.account)
            guard.withLock {
                if (generation != expectedGeneration) throw InvalidSession()
                store.write(replacement); tokens = replacement; replacement
            }
        } catch (cancelled: CancellationException) {
            withContext(NonCancellable) { endSession(expectedGeneration) }
            throw cancelled
        }
        catch (failure: Exception) {
            endSession(expectedGeneration)
            throw failure
        }
    }

    private suspend fun endSession(expectedGeneration: Long) = withContext(NonCancellable) { guard.withLock {
        if (generation == expectedGeneration) {
            generation = Math.incrementExact(generation); tokens = null; pending = null
            mutable.value = OrdersState(notice = Notice.SessionEnded)
            try { store.clear() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutable.value = OrdersState(notice = Notice.LocalSignOutFailed) }
        }
    } }

    suspend fun signOut() {
        val old = guard.withLock {
            generation = Math.incrementExact(generation); request = Math.incrementExact(request)
            revocationPending = tokens?.refreshToken ?: revocationPending
            tokens = null; pending = null
            mutable.value = OrdersState(notice = Notice.SignedOut)
            try { withContext(NonCancellable) { store.clear() } } catch (cancelled: CancellationException) { throw cancelled } catch (_: Exception) {
                mutable.value = OrdersState(notice = Notice.LocalSignOutFailed); return
            }
            generation to revocationPending
        }
        val revoked = old.second?.let {
            try { api.revoke(it); true } catch (cancelled: CancellationException) { throw cancelled } catch (_: Exception) { false }
        } ?: true
        guard.withLock {
            if (generation == old.first) {
                if (revoked) revocationPending = null
                mutable.value = OrdersState(notice = if (revoked) Notice.SignedOut else Notice.RemoteSignOutUnconfirmed)
            }
        }
    }
}
