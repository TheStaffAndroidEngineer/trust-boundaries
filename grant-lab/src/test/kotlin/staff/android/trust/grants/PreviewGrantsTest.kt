package staff.android.trust.grants

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class PreviewGrantsTest {
    private val subject: GrantAdmission = when (System.getProperty("grant.solution", "reference")) {
        "reference" -> ReferenceGrants
        "learner" -> LearnerGrants
        else -> error("grant.solution must be learner or reference")
    }
    private val scope = SessionScope("north", "maya", 7)
    private val policy = PreviewPolicy("field.documents", 1_024)
    private val grant = PreviewGrant("grant-9", scope, "report-7", 200, 800)
    private val request = PreviewRequest("grant-9", "content://field.documents/documents/report-7")
    private fun permit() = PreviewPermit("grant-9", scope, "field.documents", "report-7",
        request.rawUri, 200, 800)
    private fun admit(uri: String) = subject.admit(policy, scope, grant, request.copy(rawUri = uri), 100)
    private fun denied(reason: Denial, actual: Admission) = assertEquals(Admission.Denied(reason), actual)
    private fun completion(reason: Denial, actual: Completion) = assertEquals(Completion.Denied(reason), actual)

    @Test fun matchingGrantCarriesExactAuthorityScopeAndBound() {
        assertEquals(Admission.Permitted(permit()), subject.admit(policy, scope, grant, request, 100))
    }

    @Test fun policyAndGrantEachLimitTheReadWithoutAddingThem() {
        for (policyLimit in listOf(1L, 799L, 800L, 801L, Long.MAX_VALUE)) {
            for (grantLimit in listOf(1L, 799L, 800L, 801L, Long.MAX_VALUE)) {
                val result = subject.admit(policy.copy(maxPreviewBytes = policyLimit), scope,
                    grant.copy(maxBytes = grantLimit), request, 100)
                val accepted = assertInstanceOf(Admission.Permitted::class.java, result)
                assertEquals(minOf(policyLimit, grantLimit), accepted.permit.byteLimit)
            }
        }
    }

    @Test fun signedOutPrecedesUnknownGrantAndMalformedLocator() {
        denied(Denial.SignedOut, subject.admit(policy, null, grant, PreviewRequest("other", "%"), 100))
    }

    @Test fun unknownGrantPrecedesChangedScopeAndExpiry() {
        denied(Denial.UnknownGrant, subject.admit(policy, scope.copy(generation = 8), grant,
            request.copy(grantId = "other"), 200))
    }

    @Test fun scopeChangePrecedesExpiryAndMalformedLocator() {
        denied(Denial.ScopeChanged, subject.admit(policy, scope.copy(generation = 8), grant,
            request.copy(rawUri = "%"), 200))
    }

    @Test fun tenantAccountAndGenerationAreIndependentAuthorityDimensions() {
        for (current in listOf(scope.copy(tenantId = "south"), scope.copy(accountId = "leo"),
            scope.copy(generation = 8))) {
            denied(Denial.ScopeChanged, subject.admit(policy, current, grant, request, 100))
        }
    }

    @Test fun expiryIsExclusiveAndPrecedesLocatorParsing() {
        assertInstanceOf(Admission.Permitted::class.java, subject.admit(policy, scope, grant, request, 199))
        denied(Denial.Expired, subject.admit(policy, scope, grant, request.copy(rawUri = "%"), 200))
        denied(Denial.Expired, subject.admit(policy, scope, grant, request, 201))
    }

    @Test fun expiryAtLongMaximumStillUsesComparison() {
        assertInstanceOf(Admission.Permitted::class.java,
            subject.admit(policy, scope, grant.copy(expiresAtMillis = Long.MAX_VALUE), request, Long.MAX_VALUE - 1))
        denied(Denial.Expired,
            subject.admit(policy, scope, grant.copy(expiresAtMillis = Long.MAX_VALUE), request, Long.MAX_VALUE))
    }

    @Test fun exactAuthorityRejectsSuffixAndCaseAliases() {
        for (authority in listOf("field.documents.evil", "evilfield.documents", "FIELD.documents",
            "field.documents.", "field%2edocuments")) {
            denied(Denial.WrongAuthority, admit("content://$authority/documents/report-7"))
        }
    }

    @Test fun schemesAreExactAndHierarchical() {
        for (uri in listOf("https://field.documents/documents/report-7", "CONTENT://field.documents/documents/report-7",
            "content:report-7", "/documents/report-7", "content:/documents/report-7")) {
            denied(Denial.InvalidUri, admit(uri))
        }
    }

    @Test fun userInfoAndPortsNeverSelectTheAllowedProvider() {
        for (authority in listOf("attacker@field.documents", "field.documents@evil", "field.documents:443",
            "field.documents:", "field.documents:invalid")) {
            denied(Denial.InvalidUri, admit("content://$authority/documents/report-7"))
        }
    }

    @Test fun queryAndFragmentAreRejectedEvenWhenEmpty() {
        for (suffix in listOf("?", "?grant=grant-9", "#", "#report-7")) {
            denied(Denial.InvalidUri, admit(request.rawUri + suffix))
        }
    }

    @Test fun encodedAliasesAndPathTraversalAreNotDecoded() {
        for (path in listOf("/documents/%72eport-7", "/documents/report%2d7", "/documents/report%2F7",
            "/documents/../report-7", "/documents/./report-7", "/documents/%2e%2e", "/documents/report-7/",
            "//documents/report-7", "/document/report-7", "/documents/report-7/extra")) {
            denied(Denial.InvalidUri, admit("content://field.documents$path"))
        }
    }

    @Test fun malformedAndOversizedRequestsDenyInsteadOfThrowing() {
        for (uri in listOf("", "%", "content://[broken/documents/report-7", "\n" + request.rawUri,
            request.rawUri + " ", "x".repeat(2_049))) {
            denied(Denial.InvalidUri, admit(uri))
        }
    }

    @Test fun documentIdentityIsExactAfterStructureAndAuthorityPass() {
        denied(Denial.WrongDocument, admit("content://field.documents/documents/report-8"))
        denied(Denial.WrongDocument, admit("content://field.documents/documents/Report-7"))
        denied(Denial.WrongAuthority, admit("content://other.documents/documents/report-8"))
    }

    @Test fun documentIdentifiersHaveExplicitLengthAndAsciiRules() {
        val longest = "R".repeat(64)
        assertInstanceOf(Admission.Permitted::class.java, subject.admit(policy, scope,
            grant.copy(documentId = longest), request.copy(rawUri = "content://field.documents/documents/$longest"), 100))
        for (id in listOf("R".repeat(65), "rêport", "-report", "report.7")) {
            denied(Denial.InvalidUri, admit("content://field.documents/documents/$id"))
        }
    }

    @Test fun badTrustedPolicyThrowsEvenWhenSignedOut() {
        for (bad in listOf(policy.copy(authority = "Field.documents"), policy.copy(authority = "field"),
            policy.copy(authority = "field.documents:443"), policy.copy(maxPreviewBytes = 0),
            policy.copy(maxPreviewBytes = -1))) {
            assertThrows(IllegalArgumentException::class.java) { subject.admit(bad, null, grant, request, 100) }
        }
    }

    @Test fun badTrustedGrantThrowsEvenWhenSignedOut() {
        for (bad in listOf(grant.copy(id = ""), grant.copy(documentId = "../report"), grant.copy(maxBytes = 0),
            grant.copy(expiresAtMillis = -1), grant.copy(scope = scope.copy(generation = -1)))) {
            assertThrows(IllegalArgumentException::class.java) { subject.admit(policy, null, bad, request, 100) }
        }
    }

    @Test fun badTrustedSessionAndClockThrowBeforeRequestDenial() {
        for (bad in listOf(scope.copy(tenantId = ""), scope.copy(accountId = " "), scope.copy(generation = -1))) {
            assertThrows(IllegalArgumentException::class.java) { subject.admit(policy, bad, grant, request, 100) }
        }
        assertThrows(IllegalArgumentException::class.java) { subject.admit(policy, null, grant, request, -1) }
    }

    @Test fun completeAcceptsZeroAndExactLimitBytesWithinTime() {
        assertEquals(Completion.Allowed, subject.complete(permit(), scope.copy(), 100, 0))
        assertEquals(Completion.Allowed, subject.complete(permit(), scope, 199, 800))
    }

    @Test fun logoutPrecedesExpiryAndOversizeAtCompletion() {
        completion(Denial.SignedOut, subject.complete(permit(), null, 200, 801))
    }

    @Test fun sameAccountReauthenticationStillRejectsTheOldPermit() {
        completion(Denial.ScopeChanged, subject.complete(permit(), scope.copy(generation = 8), 150, 800))
    }

    @Test fun accountAndTenantChangesRejectCompletion() {
        for (current in listOf(scope.copy(accountId = "leo"), scope.copy(tenantId = "south"))) {
            completion(Denial.ScopeChanged, subject.complete(permit(), current, 150, 800))
        }
    }

    @Test fun changedScopePrecedesExpiredOrOversizeCompletion() {
        completion(Denial.ScopeChanged, subject.complete(permit(), scope.copy(generation = 8), 200, 801))
    }

    @Test fun completionExpiryIsExclusiveAndPrecedesByteLimit() {
        completion(Denial.Expired, subject.complete(permit(), scope, 200, 801))
    }

    @Test fun oneByteOverTheBudgetRejectsPublication() {
        completion(Denial.TooManyBytes, subject.complete(permit(), scope, 150, 801))
    }

    @Test fun negativeActualBytesAreAnAdapterErrorEvenWhenSignedOut() {
        assertThrows(IllegalArgumentException::class.java) { subject.complete(permit(), null, 150, -1) }
    }

    @Test fun invalidCompletionContextOrClockThrows() {
        assertThrows(IllegalArgumentException::class.java) { subject.complete(permit(), scope.copy(generation = -1), 150, 0) }
        assertThrows(IllegalArgumentException::class.java) { subject.complete(permit(), null, -1, 0) }
    }

    @Test fun structurallyInvalidPermitThrowsEvenWhenSignedOut() {
        for (bad in listOf(permit().copy(byteLimit = 0), permit().copy(expiresAtMillis = -1),
            permit().copy(scope = scope.copy(accountId = "")), permit().copy(canonicalUri = request.rawUri + "?"),
            permit().copy(authority = "FIELD.documents"), permit().copy(grantId = ""))) {
            assertThrows(IllegalArgumentException::class.java) { subject.complete(bad, null, 100, 0) }
        }
    }

    @Test fun modelsDoNotClaimToDetectUnreportedRevocation() {
        // No current-grant/revocation input exists: a real adapter must supply that check.
        assertEquals(Completion.Allowed, subject.complete(permit(), scope, 150, 1))
    }
}
