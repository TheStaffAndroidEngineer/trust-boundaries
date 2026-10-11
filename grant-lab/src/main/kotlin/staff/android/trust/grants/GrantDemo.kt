package staff.android.trust.grants

fun main() {
    val scope = SessionScope("north", "maya", 7)
    val policy = PreviewPolicy("field.documents", 1_024)
    val grant = PreviewGrant("grant-9", scope, "report-7", 200, 800)
    val request = PreviewRequest("grant-9", "content://field.documents/documents/report-7")
    val permit = (ReferenceGrants.admit(policy, scope, grant, request, 100)
        as Admission.Permitted).permit
    println("ADMIT scope=${permit.scope} limit=${permit.byteLimit} expires=${permit.expiresAtMillis}")
    println("COMPLETE same scope: ${ReferenceGrants.complete(permit, scope, 150, 800)}")
    println("COMPLETE same account, new generation: ${ReferenceGrants.complete(permit, scope.copy(generation = 8), 150, 800)}")
    println("COMPLETE at expiry: ${ReferenceGrants.complete(permit, scope, 200, 800)}")
    println("AUTHORITY suffix: ${ReferenceGrants.admit(policy, scope, grant, request.copy(rawUri = "content://field.documents.evil/documents/report-7"), 100)}")
}
