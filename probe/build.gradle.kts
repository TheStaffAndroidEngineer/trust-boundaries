plugins { alias(libs.plugins.androidApplication) }
android {
    namespace = "staff.android.trust.probe"
    compileSdk { version = release(37) { minorApiLevel = 1 } }
    buildToolsVersion = "37.0.0"
    defaultConfig { applicationId = "staff.android.trust.probe"; minSdk = 26; targetSdk = 37; versionCode = 1; versionName = "1.0" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_26; targetCompatibility = JavaVersion.VERSION_26 }
}
kotlin { jvmToolchain(27); compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_26) } }
