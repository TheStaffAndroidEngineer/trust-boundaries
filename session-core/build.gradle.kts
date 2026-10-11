plugins { alias(libs.plugins.kotlinJvm); `java-library`; alias(libs.plugins.kotlinSerialization) }
kotlin { jvmToolchain(27); compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_26) } }
java { sourceCompatibility = JavaVersion.VERSION_26; targetCompatibility = JavaVersion.VERSION_26 }
tasks.withType<JavaCompile>().configureEach { options.release.set(26) }
tasks.withType<Test>().configureEach { useJUnitPlatform(); testLogging { events("passed", "failed", "skipped") } }
dependencies {
    implementation(libs.coroutinesCore)
    implementation(libs.serializationJson)
    testImplementation(libs.coroutinesTest)
    testImplementation(libs.junitJupiter)
    testRuntimeOnly(libs.junitPlatformLauncher)
}
