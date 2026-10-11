package staff.android.trust

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Trace
import android.util.LruCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.IOException

/** Process cache owns application assets, never an Activity or a View. */
class ImageStore(context: Context) {
    private val assets = context.applicationContext.assets
    private val decodeLock = Mutex()
    private val cache = object : LruCache<String, Bitmap>(8 * 1024 * 1024) {
        override fun sizeOf(key: String, value: Bitmap) = value.allocationByteCount
    }
    val cachedBytes: Int get() = cache.size()
    fun clear() = cache.evictAll()
    suspend fun load(key: String): Bitmap? = withContext(Dispatchers.IO) {
        decodeLock.withLock {
            cache.get(key) ?: run {
                Trace.beginSection("CG25/decode/$key")
                try {
                    assets.open("$key.png").use {
                        BitmapFactory.decodeStream(it, null, BitmapFactory.Options().apply { inSampleSize = 2 })
                    }?.also { cache.put(key, it) }
                } catch (_: IOException) { null }
                finally { Trace.endSection() }
            }
        }
    }
}

object ProductImages {
    private var store: ImageStore? = null
    fun get(context: Context): ImageStore = store ?: ImageStore(context).also { store = it }
}
