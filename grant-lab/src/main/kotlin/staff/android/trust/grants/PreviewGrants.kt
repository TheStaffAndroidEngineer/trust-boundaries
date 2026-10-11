package staff.android.trust.grants

import java.net.URI
import java.net.URISyntaxException

/** These immutable values are inputs to a policy model, not authenticated credentials. */
data class SessionScope(val tenantId: String, val accountId: String, val generation: Long)
data class PreviewPolicy(val authority: String, val maxPreviewBytes: Long)
data class PreviewGrant(
    val id: String,
    val scope: SessionScope,
    val documentId: String,
    val expiresAtMillis: Long,
    val maxBytes: Long,
)
data class PreviewRequest(val grantId: String, val rawUri: String)
data class PreviewPermit(
    val grantId: String,
    val scope: SessionScope,
    val authority: String,
    val documentId: String,
    val canonicalUri: String,
    val expiresAtMillis: Long,
    val byteLimit: Long,
)
enum class Denial {
    SignedOut, UnknownGrant, ScopeChanged, Expired,
    InvalidUri, WrongAuthority, WrongDocument, TooManyBytes,
}
sealed interface Admission {
    data class Permitted(val permit: PreviewPermit) : Admission
    data class Denied(val reason: Denial) : Admission
}
sealed interface Completion {
    data object Allowed : Completion
    data class Denied(val reason: Denial) : Completion
}
interface GrantAdmission {
    fun admit(
        policy: PreviewPolicy, session: SessionScope?, grant: PreviewGrant,
        request: PreviewRequest, nowMillis: Long,
    ): Admission
    fun complete(
        permit: PreviewPermit, currentSession: SessionScope?,
        nowMillis: Long, actualBytes: Long,
    ): Completion
}

/** Deliberately unfinished. Implement both contracts without delegating to ReferenceGrants. */
object LearnerGrants : GrantAdmission {
    override fun admit(
        policy: PreviewPolicy, session: SessionScope?, grant: PreviewGrant,
        request: PreviewRequest, nowMillis: Long,
    ): Admission = Admission.Denied(Denial.SignedOut)

    override fun complete(
        permit: PreviewPermit, currentSession: SessionScope?,
        nowMillis: Long, actualBytes: Long,
    ): Completion = Completion.Allowed
}

/**
 * A bounded pure model. The adapter must authenticate the grant, verify current OS
 * permission, enforce the stream limit before allocation, and decide revocation policy.
 * Neither constructing these data classes nor receiving Allowed performs those actions.
 */
object ReferenceGrants : GrantAdmission {
    private val identifier = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
    private val authorityName = Regex("[a-z][a-z0-9]*(?:\\.[a-z][a-z0-9]*)+")
    private val documentPath = Regex("/documents/([A-Za-z0-9][A-Za-z0-9_-]{0,63})")

    override fun admit(
        policy: PreviewPolicy, session: SessionScope?, grant: PreviewGrant,
        request: PreviewRequest, nowMillis: Long,
    ): Admission {
        validateAuthority(policy.authority)
        require(policy.maxPreviewBytes > 0)
        validateGrant(grant)
        session?.let(::validateScope)
        require(nowMillis >= 0)
        if (session == null) return Admission.Denied(Denial.SignedOut)
        if (request.grantId != grant.id) return Admission.Denied(Denial.UnknownGrant)
        if (session != grant.scope) return Admission.Denied(Denial.ScopeChanged)
        if (nowMillis >= grant.expiresAtMillis) return Admission.Denied(Denial.Expired)
        val uri = parseLocator(request.rawUri)
            ?: return Admission.Denied(Denial.InvalidUri)
        if (uri.rawAuthority != policy.authority) {
            return Admission.Denied(Denial.WrongAuthority)
        }
        val documentId = documentPath.matchEntire(uri.rawPath)!!.groupValues[1]
        if (documentId != grant.documentId) {
            return Admission.Denied(Denial.WrongDocument)
        }
        return Admission.Permitted(PreviewPermit(
            grantId = grant.id,
            scope = session,
            authority = policy.authority,
            documentId = documentId,
            canonicalUri = "content://${policy.authority}/documents/$documentId",
            expiresAtMillis = grant.expiresAtMillis,
            byteLimit = minOf(policy.maxPreviewBytes, grant.maxBytes),
        ))
    }

    override fun complete(
        permit: PreviewPermit, currentSession: SessionScope?,
        nowMillis: Long, actualBytes: Long,
    ): Completion {
        validatePermit(permit)
        currentSession?.let(::validateScope)
        require(nowMillis >= 0 && actualBytes >= 0)
        if (currentSession == null) return Completion.Denied(Denial.SignedOut)
        if (currentSession != permit.scope) return Completion.Denied(Denial.ScopeChanged)
        if (nowMillis >= permit.expiresAtMillis) return Completion.Denied(Denial.Expired)
        if (actualBytes > permit.byteLimit) return Completion.Denied(Denial.TooManyBytes)
        return Completion.Allowed
    }

    private fun parseLocator(raw: String): URI? {
        if (raw.length !in 1..2_048) return null
        val uri = try { URI(raw) } catch (_: URISyntaxException) { return null }
        if (uri.scheme != "content" || uri.isOpaque || uri.rawAuthority.isNullOrEmpty()) {
            return null
        }
        if (uri.rawUserInfo != null || ':' in uri.rawAuthority || '@' in uri.rawAuthority) {
            return null
        }
        if (uri.rawQuery != null || uri.rawFragment != null) return null
        if (uri.rawPath == null || !documentPath.matches(uri.rawPath)) return null
        return uri
    }

    private fun validateScope(scope: SessionScope) {
        require(identifier.matches(scope.tenantId) && identifier.matches(scope.accountId))
        require(scope.generation >= 0)
    }

    private fun validateAuthority(authority: String) {
        require(authority.length <= 253 && authorityName.matches(authority))
    }

    private fun validateGrant(grant: PreviewGrant) {
        require(identifier.matches(grant.id) && identifier.matches(grant.documentId))
        validateScope(grant.scope)
        require(grant.expiresAtMillis >= 0 && grant.maxBytes > 0)
    }

    private fun validatePermit(permit: PreviewPermit) {
        require(identifier.matches(permit.grantId) && identifier.matches(permit.documentId))
        validateScope(permit.scope)
        validateAuthority(permit.authority)
        require(permit.expiresAtMillis >= 0 && permit.byteLimit > 0)
        require(permit.canonicalUri ==
            "content://${permit.authority}/documents/${permit.documentId}")
    }
}
