package staff.android.trust.probe

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Process
import org.json.JSONObject
import java.io.File

/** Separate-UID local abuse probe; never accepts arbitrary packages, paths or URLs. */
class BoundaryProbe : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val name = intent.getStringExtra("case") ?: "private_activity"
        val result = JSONObject().put("case", name).put("callerUid", Process.myUid())
        when (name) {
            "private_activity" -> {
                val component = ComponentName("staff.android.trust", "staff.android.trust.OrdersActivity")
                val declaration = context.packageManager.getActivityInfo(component, 0)
                result.put("declaredComponent", declaration.name).put("exported", declaration.exported)
                try {
                    context.startActivity(Intent().setClassName("staff.android.trust", "staff.android.trust.OrdersActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    result.put("outcome", "UNEXPECTED_ALLOWED")
                } catch (_: SecurityException) { result.put("outcome", "DENIED_SECURITY_EXCEPTION") }
                catch (_: ActivityNotFoundException) { result.put("outcome", "DENIED_OR_NOT_RESOLVED") }
            }
            "private_storage" -> {
                try {
                    File("/data/user/0/staff.android.trust/no_backup/session.bin").inputStream().use { it.read() }
                    result.put("outcome", "UNEXPECTED_READABLE")
                } catch (_: java.io.IOException) { result.put("outcome", "READ_DENIED_OR_ABSENT") }
            }
            "foreign_receipt", "malformed_link", "forged_extras" -> {
                val uri = if (name == "malformed_link") "https://commongoods.example.evil/orders/cg-2088" else "https://commongoods.example/orders/cg-2088"
                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(uri)).setClassName("staff.android.trust", "staff.android.trust.MainActivity")
                    .putExtra("accountId", "leo").putExtra("ownerId", "leo").putExtra("accessToken", "forged-probe-value")
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                result.put("outcome", "PUBLIC_ENTRY_REQUESTED")
            }
            else -> result.put("outcome", "UNKNOWN_CASE")
        }
        File(context.filesDir, "probe-result.json").writeText(result.toString(2))
    }
}
