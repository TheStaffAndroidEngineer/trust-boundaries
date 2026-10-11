package staff.android.trust

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.encodeToString
import staff.android.trust.session.*
import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Purpose-bound authenticated ciphertext. No promise of hardware-backed or per-use-auth keys. */
class SecureSessionStore(context: Context) : SessionStore {
    private val guard = Mutex()
    private val base = File(context.noBackupFilesDir, "session.bin")
    private val file = AtomicFile(base)
    private val aad = "CommonGoods.Session.v1|staff.android.trust".toByteArray()
    private fun readBounded(): ByteArray = file.openRead().use { input ->
        val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(1024)
        while (true) {
            val count = input.read(buffer); if (count < 0) break
            require(output.size() + count <= 16_384)
            output.write(buffer, 0, count)
        }
        output.toByteArray()
    }
    private fun keys() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun key(create: Boolean): SecretKey? {
        val existing = keys().getKey(alias, null) as? SecretKey
        if (existing != null || !create) return existing
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    private fun clearRecord() {
        // Destroying the key makes residual ciphertext unusable if file deletion fails.
        val keyStore = keys()
        val keyRemoved = runCatching { keyStore.deleteEntry(alias); !keyStore.containsAlias(alias) }.getOrDefault(false)
        file.delete()
        val fileRemoved = listOf(base, File(base.path + ".bak"), File(base.path + ".new")).none { it.exists() }
        if (!keyRemoved && !fileRemoved) throw IOException("Session removal could not be confirmed")
    }
    override suspend fun clear() = withContext(Dispatchers.IO) { guard.withLock { clearRecord() } }
    override suspend fun read(): Tokens? = withContext(Dispatchers.IO) {
        guard.withLock {
            if (!base.exists() && !File(base.path + ".bak").exists()) return@withLock null
            try {
                val data = readBounded()
                val parts = data.decodeToString(throwOnInvalidSequence = true).split('\n')
                require(parts.size == 3 && parts[0] == "1")
                val iv = Base64.getDecoder().decode(parts[1]); require(iv.size == 12)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key(false) ?: throw IOException("Session key unavailable"), GCMParameterSpec(128, iv))
                cipher.updateAAD(aad)
                val plaintext = cipher.doFinal(Base64.getDecoder().decode(parts[2]))
                try { SessionCodec.validate(SessionCodec.json.decodeFromString<Tokens>(plaintext.decodeToString(throwOnInvalidSequence = true))) }
                finally { plaintext.fill(0) }
            } catch (_: Exception) { clearRecord(); null }
        }
    }
    override suspend fun write(tokens: Tokens) = withContext(Dispatchers.IO) {
        guard.withLock {
            SessionCodec.validate(tokens)
            val plaintext = SessionCodec.json.encodeToString(tokens).toByteArray()
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key(true)); cipher.updateAAD(aad)
                // The provider generates a fresh randomized IV for each encryption.
                val ciphertext = cipher.doFinal(plaintext)
                val data = "1\n" + Base64.getEncoder().encodeToString(cipher.iv) + "\n" + Base64.getEncoder().encodeToString(ciphertext)
                val output = file.startWrite()
                try { output.write(data.toByteArray()); output.fd.sync(); file.finishWrite(output) }
                catch (failure: Exception) { file.failWrite(output); throw failure }
                val readback = readBounded()
                if (!readback.contentEquals(data.toByteArray())) throw IOException("Session commit could not be confirmed")
            } catch (failure: Exception) { clearRecord(); throw failure }
            finally { plaintext.fill(0) }
        }
    }
    companion object { const val alias = "common-goods-session-v1" }
}
