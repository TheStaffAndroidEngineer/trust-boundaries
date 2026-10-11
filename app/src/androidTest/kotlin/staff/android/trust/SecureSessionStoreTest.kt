package staff.android.trust

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.security.KeyStore
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import staff.android.trust.session.Account
import staff.android.trust.session.Tokens

/** Real AndroidKeystore/AtomicFile checks with synthetic, non-authorizing tokens. */
@RunWith(AndroidJUnit4::class)
class SecureSessionStoreTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val file get() = File(context.noBackupFilesDir, "session.bin")
    private val tokens = Tokens(Account("maya", "Maya"), "ACCESS_SYNTHETIC_".repeat(3), "REFRESH_SYNTHETIC_".repeat(3), 123_456L)
    private fun keys() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Before fun before() = runBlocking<Unit> {
        // Wait for process restoration before touching its storage fixture.
        (context.applicationContext as GoodsApplication).ready.await()
        (context.applicationContext as GoodsApplication).controller.signOut()
        SecureSessionStore(context).clear()
    }

    @After fun after() = runBlocking<Unit> { SecureSessionStore(context).clear() }

    @Test fun newStoreRestoresCiphertextWithoutPersistedTokenPlaintext() = runBlocking<Unit> {
        SecureSessionStore(context).write(tokens)
        assertTrue(file.isFile)
        assertEquals(context.noBackupFilesDir.canonicalFile, file.parentFile.canonicalFile)
        val raw = file.readText()
        assertFalse(raw.contains(tokens.accessToken)); assertFalse(raw.contains(tokens.refreshToken))
        assertFalse(raw.contains("\"account\"")); assertEquals("1", raw.lineSequence().first())
        assertEquals(tokens, SecureSessionStore(context).read())
    }

    @Test fun repeatedWriteUsesDistinctProviderIvAndStillRestores() = runBlocking<Unit> {
        val store = SecureSessionStore(context); store.write(tokens)
        val first = file.readText().split('\n'); store.write(tokens); val second = file.readText().split('\n')
        assertEquals(12, Base64.getDecoder().decode(first[1]).size)
        assertEquals(12, Base64.getDecoder().decode(second[1]).size)
        assertNotEquals(first[1], second[1]); assertNotEquals(first[2], second[2])
        assertEquals(tokens, SecureSessionStore(context).read())
    }

    @Test fun changedCiphertextIsRejectedAndItsKeyAndRecordAreRemoved() = runBlocking<Unit> {
        val store = SecureSessionStore(context); store.write(tokens)
        val parts = file.readText().split('\n').toMutableList()
        val ciphertext = Base64.getDecoder().decode(parts[2]); ciphertext[0] = (ciphertext[0].toInt() xor 1).toByte()
        parts[2] = Base64.getEncoder().encodeToString(ciphertext); file.writeText(parts.joinToString("\n"))
        assertNull(SecureSessionStore(context).read())
        assertFalse(file.exists()); assertFalse(keys().containsAlias(SecureSessionStore.alias))
    }

    @Test fun missingKeyDoesNotGenerateReplacementAndAcceptOldCiphertext() = runBlocking<Unit> {
        SecureSessionStore(context).write(tokens); keys().deleteEntry(SecureSessionStore.alias)
        assertNull(SecureSessionStore(context).read())
        assertFalse(file.exists()); assertFalse(keys().containsAlias(SecureSessionStore.alias))
    }

    @Test fun unknownVersionMalformedIvAndOversizedEnvelopeFailClosed() = runBlocking<Unit> {
        val corruptions: List<(String) -> ByteArray> = listOf(
            { it.replaceFirst("1\n", "2\n").toByteArray() },
            { val p = it.split('\n').toMutableList(); p[1] = Base64.getEncoder().encodeToString(ByteArray(11)); p.joinToString("\n").toByteArray() },
            { ByteArray(16_385) { 'X'.code.toByte() } },
            { byteArrayOf(0xC3.toByte(), 0x28) },
        )
        for (corrupt in corruptions) {
            SecureSessionStore(context).write(tokens); file.writeBytes(corrupt(file.readText()))
            assertNull(SecureSessionStore(context).read()); assertFalse(file.exists())
            assertFalse(keys().containsAlias(SecureSessionStore.alias))
        }
    }

    @Test fun clearMakesCopiedOldCiphertextUnrestorable() = runBlocking<Unit> {
        val store = SecureSessionStore(context); store.write(tokens); val old = file.readBytes()
        store.clear(); assertFalse(file.exists()); assertFalse(keys().containsAlias(SecureSessionStore.alias))
        file.writeBytes(old)
        assertNull(SecureSessionStore(context).read()); assertFalse(file.exists())
    }

    @Test fun invalidTrustedWriteDoesNotReplacePreviouslyUsableRecord() = runBlocking<Unit> {
        val store = SecureSessionStore(context); store.write(tokens); val before = file.readBytes()
        try { store.write(tokens.copy(accessToken = "bad")); fail("Malformed trusted token was accepted") }
        catch (_: IllegalArgumentException) { /* Boundary validation precedes the write. */ }
        assertArrayEquals(before, file.readBytes()); assertEquals(tokens, SecureSessionStore(context).read())
    }
}
