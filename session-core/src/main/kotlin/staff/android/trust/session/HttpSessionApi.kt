package staff.android.trust.session

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/** Development loopback fixture only. Logs never receive request/response secrets. */
class HttpSessionApi(private val baseUrl: String = "http://127.0.0.1:8875") : SessionApi {
    override suspend fun exchange(code: String, verifier: String): Tokens = token(linkedMapOf(
        "grant_type" to "authorization_code", "client_id" to EntryPolicy.clientId,
        "redirect_uri" to EntryPolicy.callback, "code" to code, "code_verifier" to verifier))
    override suspend fun refresh(refreshToken: String): Tokens = token(linkedMapOf(
        "grant_type" to "refresh_token", "client_id" to EntryPolicy.clientId, "refresh_token" to refreshToken))
    private suspend fun token(values: Map<String, String>): Tokens = SessionCodec.validate(
        SessionCodec.json.decodeFromString<Tokens>(request("POST", "/token", values = values)))
    override suspend fun revoke(refreshToken: String) { request("POST", "/revoke", values = mapOf("token" to refreshToken)) }
    override suspend fun orders(accessToken: String): List<OrderSummary> = SessionCodec.json.decodeFromString(request("GET", "/orders", accessToken))
    override suspend fun receipt(accessToken: String, id: String): Receipt {
        require(EntryPolicy.validId(id))
        return SessionCodec.json.decodeFromString(request("GET", "/orders/$id", accessToken))
    }
    private suspend fun request(method: String, path: String, bearer: String? = null, values: Map<String, String>? = null): String = withContext(Dispatchers.IO) {
        val connection = URI(baseUrl + path).toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = 5_000; connection.readTimeout = 5_000
            connection.instanceFollowRedirects = false; connection.useCaches = false
            connection.setRequestProperty("Accept", "application/json")
            if (bearer != null) connection.setRequestProperty("Authorization", "Bearer $bearer")
            if (values != null) {
                val data = values.entries.joinToString("&") { (key, value) -> key + "=" + URLEncoder.encode(value, "UTF-8") }.toByteArray()
                connection.doOutput = true; connection.setFixedLengthStreamingMode(data.size)
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                connection.outputStream.use { it.write(data) }
            }
            val status = connection.responseCode
            if (status !in 200..299) throw ServiceFailure(status)
            val bytes = connection.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(4096)
                while (true) {
                    currentCoroutineContext().ensureActive()
                    val count = input.read(buffer); if (count < 0) break
                    if (output.size() + count > 65_536) throw java.io.IOException("Response exceeds bound")
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            bytes.decodeToString(throwOnInvalidSequence = true)
        } finally { connection.disconnect() }
    }
}
