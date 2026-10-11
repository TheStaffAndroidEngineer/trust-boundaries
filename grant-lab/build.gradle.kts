plugins { alias(libs.plugins.kotlinJvm); application }
kotlin { jvmToolchain(27); compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_26) } }
java { sourceCompatibility = JavaVersion.VERSION_26; targetCompatibility = JavaVersion.VERSION_26 }
tasks.withType<JavaCompile>().configureEach { options.release.set(26) }
application { mainClass.set("staff.android.trust.grants.GrantDemoKt") }
dependencies {
    testImplementation(libs.junitJupiter)
    testRuntimeOnly(libs.junitPlatformLauncher)
}
tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    systemProperty("grant.solution", providers.gradleProperty("grantSolution").getOrElse("reference"))
    testLogging { events("passed", "failed", "skipped") }
}
