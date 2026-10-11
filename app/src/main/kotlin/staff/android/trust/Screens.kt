package staff.android.trust

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.grid.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import staff.android.trust.session.*
import java.text.NumberFormat
import java.util.Locale

@Composable fun BookWindow(content: @Composable () -> Unit) {
    CommonTheme {
        Surface(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.systemBars)) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
                Box(Modifier.widthIn(max = 960.dp).fillMaxWidth().semantics { testTagsAsResourceId = true }) { content() }
            }
        }
    }
}
@Composable fun Brand(action: String, onAction: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Image(painterResource(R.drawable.ic_common_goods), null, Modifier.size(40.dp))
        Spacer(Modifier.width(10.dp))
        Text("Common Goods", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
        TextButton(onClick = onAction) { Text(action) }
    }
}
@Composable fun ProductPhoto(product: Product, modifier: Modifier) {
    val context = LocalContext.current
    val store = remember(context.applicationContext) { ProductImages.get(context) }
    val bitmap by produceState<android.graphics.Bitmap?>(null, product.imageKey) { value = store.load(product.imageKey) }
    Box(modifier.clip(RoundedCornerShape(20.dp)).background(MaterialTheme.colorScheme.surfaceVariant), contentAlignment = Alignment.Center) {
        if (bitmap != null) Image(bitmap!!.asImageBitmap(), product.title, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
        else Text("Your collection", Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium)
    }
}
fun amount(value: Long): String = NumberFormat.getCurrencyInstance(Locale.forLanguageTag("en-IN")).apply { maximumFractionDigits = 0 }.format(value / 100.0)

@Composable fun ShopScreen(controller: SessionController, openOrders: () -> Unit) {
    val state by controller.state.collectAsStateWithLifecycle()
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    val product = Catalog.featured.firstOrNull { it.id == selected }
    BackHandler(product != null) { selected = null }
    if (product != null) {
        LazyColumn(Modifier.fillMaxSize().testTag("product_detail"), contentPadding = PaddingValues(bottom = 28.dp), verticalArrangement = Arrangement.spacedBy(18.dp)) {
            item { Brand("Back") { selected = null } }
            item { ProductPhoto(product, Modifier.fillMaxWidth().padding(horizontal = 20.dp).aspectRatio(1.25f)) }
            item { Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Text(product.title, style = MaterialTheme.typography.displaySmall)
                Text(product.price, style = MaterialTheme.typography.headlineSmall)
                Text(product.description, style = MaterialTheme.typography.bodyLarge)
                OutlinedButton(onClick = openOrders, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) { Text("Your orders") }
            } }
        }
        return
    }
    val configuration = LocalConfiguration.current
    val columns = if (configuration.fontScale >= 1.5f) 1 else if (configuration.screenWidthDp >= 700) 3 else 2
    LazyVerticalGrid(GridCells.Fixed(columns), Modifier.fillMaxSize().testTag("shop"),
        contentPadding = PaddingValues(bottom = 28.dp), horizontalArrangement = Arrangement.spacedBy(16.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {
        item(span = { GridItemSpan(maxLineSpan) }) { Brand("Orders", openOrders) }
        item(span = { GridItemSpan(maxLineSpan) }) {
            Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Good things,\nevery day.", style = MaterialTheme.typography.displaySmall)
                Text("A considered collection for everyday living.", style = MaterialTheme.typography.bodyLarge)
                if (state.notice == Notice.InvalidLink) Text("This link couldn't be opened. Find your purchases in Your orders.", Modifier.testTag("invalid_link"), color = MaterialTheme.colorScheme.error)
                OutlinedButton(onClick = openOrders, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("open_orders")) { Text("Your orders") }
            }
        }
        items(Catalog.featured, key = { it.id }) { item ->
            Column(Modifier.padding(horizontal = 12.dp)) {
                ProductPhoto(item, Modifier.fillMaxWidth().aspectRatio(1f))
                Text(item.title, Modifier.padding(top = 12.dp), style = MaterialTheme.typography.titleMedium)
                Text(item.price, style = MaterialTheme.typography.bodyLarge)
                TextButton(onClick = { selected = item.id }, contentPadding = PaddingValues(0.dp)) { Text("Explore ${item.title}") }
            }
        }
    }
}

private fun noticeText(value: Notice) = when (value) {
    Notice.SignInRequired -> "Sign in to see your purchases and receipts."
    Notice.InvalidLink -> "This link couldn't be opened. Use your order list or try signing in again."
    Notice.SignInFailed -> "Sign-in wasn't completed. Please try again."
    Notice.Unavailable -> "We couldn't open this receipt. Check the link or use your order list."
    Notice.Retry -> "We couldn't load this right now. Your connection may be unavailable."
    Notice.SessionEnded -> "Your session has ended. Sign in again to see your orders."
    Notice.SignedOut -> "You're signed out of this app."
    Notice.LocalSignOutFailed -> "Sign-out could not be saved. Please try again."
    Notice.RemoteSignOutUnconfirmed -> "You're signed out here. We couldn't confirm the server sign-out while offline."
}
@Composable fun OrdersScreen(controller: SessionController, shop: () -> Unit, signIn: () -> Unit, run: (suspend () -> Unit) -> Unit) {
    val state by controller.state.collectAsStateWithLifecycle()
    val large = LocalConfiguration.current.fontScale >= 1.5f
    val back = { if (state.requestedId != null && state.account != null) run { controller.loadOrders() } else shop() }
    BackHandler { back() }
    LazyColumn(Modifier.fillMaxSize().testTag("orders_screen"), contentPadding = PaddingValues(bottom = 32.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {
        item { Brand(if (state.requestedId != null && state.account != null) "All orders" else "Shop", back) }
        item {
            Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(if (state.requestedId != null && state.account != null) "Your receipt." else "Good things,\nremembered.", style = MaterialTheme.typography.displaySmall)
                Text(if (state.account == null) "Your purchases, all in one place." else "Signed in as ${state.account!!.name}", Modifier.testTag("account_label"), style = MaterialTheme.typography.bodyLarge)
                state.account?.let {
                    OutlinedButton(onClick = { run { controller.signOut() } }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("sign_out")) { Text("Sign out") }
                }
                if (state.loading) {
                    LinearProgressIndicator(Modifier.fillMaxWidth().testTag("orders_loading"))
                    Text("Getting things ready…")
                }
                if (state.notice != null || state.account == null) Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = RoundedCornerShape(20.dp)) {
                    Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        Text(if (state.account == null && state.loading) "Complete sign-in in your browser, or cancel to start again." else noticeText(state.notice ?: Notice.SignInRequired), Modifier.testTag("orders_notice"), style = MaterialTheme.typography.bodyLarge)
                        if (state.notice == Notice.LocalSignOutFailed) Button(onClick = { run { controller.signOut() } }, modifier = Modifier.fillMaxWidth()) { Text("Try sign-out again") }
                        else if (state.account == null) {
                            Button(onClick = signIn, enabled = !state.loading, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("sign_in")) { Text("Sign in") }
                            if (state.loading) OutlinedButton(onClick = { run { controller.cancelLogin() } }, modifier = Modifier.fillMaxWidth().testTag("cancel_sign_in")) { Text("Cancel sign-in") }
                        }
                        else if (state.notice == Notice.Retry) Button(onClick = { run { state.requestedId?.let { controller.openReceipt(it) } ?: controller.loadOrders() } }, modifier = Modifier.fillMaxWidth().testTag("retry_orders")) { Text("Try again") }
                        else OutlinedButton(onClick = { run { controller.loadOrders() } }, modifier = Modifier.fillMaxWidth().testTag("all_orders")) { Text("View your orders") }
                    }
                }
            }
        }
        if (state.account != null && !state.loading && state.notice == null && state.requestedId == null && state.orders.isEmpty()) item {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Your next good thing awaits.", style = MaterialTheme.typography.headlineSmall)
                Text("When you place an order, you'll find its receipt here.")
                OutlinedButton(onClick = shop) { Text("Explore the collection") }
            }
        }
        items(state.orders, key = { it.id }) { order ->
            val product = Catalog.featured.first { it.id == order.productId }
            Surface(Modifier.padding(horizontal = 20.dp).fillMaxWidth(), shape = RoundedCornerShape(20.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    ProductPhoto(product, Modifier.fillMaxWidth().aspectRatio(if (large) 1.5f else 2.2f))
                    Text(order.title, style = MaterialTheme.typography.headlineSmall)
                    Text("Order ${order.id.uppercase()} · ${amount(order.totalMinor)}", Modifier.testTag("order_summary"))
                    Button(onClick = { run { controller.openReceipt(order.id) } }, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("view_receipt")) { Text("View receipt") }
                }
            }
        }
        state.receipt?.let { receipt ->
            val product = Catalog.featured.first { it.id == receipt.productId }
            item { ProductPhoto(product, Modifier.fillMaxWidth().padding(horizontal = 20.dp).aspectRatio(if (large) 1.4f else 1.8f)) }
            item {
                Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp).testTag("receipt_body"), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(receipt.title, style = MaterialTheme.typography.headlineMedium)
                    Text("Order ${receipt.id.uppercase()}", Modifier.testTag("receipt_id"), style = MaterialTheme.typography.bodyLarge)
                    HorizontalDivider()
                    Text(receipt.status, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleMedium)
                    Text("Paid in full", style = MaterialTheme.typography.bodyLarge)
                    Text(amount(receipt.totalMinor), Modifier.testTag("receipt_total"), style = MaterialTheme.typography.headlineLarge)
                    Text("Thank you for choosing Common Goods.", style = MaterialTheme.typography.bodyLarge)
                    OutlinedButton(onClick = { run { controller.loadOrders() } }, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("back_orders")) { Text("Back to your orders") }
                }
            }
        }
    }
}
