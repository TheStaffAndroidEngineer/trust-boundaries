package staff.android.trust

import android.app.Application
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.browser.customtabs.CustomTabsIntent
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.*
import staff.android.trust.session.*

class GoodsApplication : Application() {
    val processScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    lateinit var controller: SessionController; private set
    lateinit var ready: Deferred<Unit>; private set
    override fun onCreate() {
        super.onCreate()
        controller = SessionController(HttpSessionApi(), SecureSessionStore(this))
        ready = processScope.async { controller.restore() }
    }
}
private const val RECEIPT = "internal_receipt_id"
private const val SKIP_LOAD = "internal_skip_load"
fun ComponentActivity.openOrders(id: String? = null, skipLoad: Boolean = false) {
    startActivity(Intent(this, OrdersActivity::class.java).putExtra(RECEIPT, id).putExtra(SKIP_LOAD, skipLoad))
}
fun ComponentActivity.signIn() {
    val app = application as GoodsApplication
    lifecycleScope.launch {
        try {
            app.ready.await()
            val url = app.controller.beginLogin("http://127.0.0.1:8875")
            CustomTabsIntent.Builder().setShowTitle(true).build().launchUrl(this@signIn, Uri.parse(url))
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { app.controller.cancelLogin() }
    }
}
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { BookWindow { ShopScreen((application as GoodsApplication).controller, { openOrders() }) } }
        dispatch(intent)
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); dispatch(intent) }
    private fun dispatch(incoming: Intent) {
        val raw = incoming.dataString ?: return
        // No external extras become account, receipt body, component or token authority.
        intent = Intent(this, MainActivity::class.java)
        val id = EntryPolicy.receiptId(raw)
        if (id != null) { openOrders(id); return }
        val app = application as GoodsApplication
        app.processScope.launch {
            app.ready.await()
            if (EntryPolicy.callbackFields(raw) != null) {
                val success = app.controller.completeLogin(raw)
                if (!success) app.controller.rejectLink(preserveExistingNotice = true)
                withContext(Dispatchers.Main) { openOrders(app.controller.state.value.requestedId, skipLoad = !success) }
            } else app.controller.rejectLink()
        }
    }
}
class OrdersActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = application as GoodsApplication
        setContent { BookWindow { OrdersScreen(app.controller, { finish() }, { signIn() }, { action -> app.processScope.launch { action() } }) } }
        if (!intent.getBooleanExtra(SKIP_LOAD, false)) {
            val id = (savedInstanceState?.getString(RECEIPT) ?: intent.getStringExtra(RECEIPT))?.takeIf(EntryPolicy::validId)
            app.processScope.launch { app.ready.await(); if (id == null) app.controller.loadOrders() else app.controller.openReceipt(id) }
        }
    }
    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString(RECEIPT, (application as GoodsApplication).controller.state.value.requestedId)
        super.onSaveInstanceState(outState)
    }
}
