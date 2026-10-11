plugins { alias(libs.plugins.androidApplication); alias(libs.plugins.kotlinCompose) }
android {
    namespace = "staff.android.trust"
    compileSdk { version = release(37) { minorApiLevel = 1 } }
    buildToolsVersion = "37.0.0"
    defaultConfig {
        applicationId = "staff.android.trust"; minSdk = 26; targetSdk = 37
        versionCode = 1; versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildTypes {
        release {
            isMinifyEnabled = true; isShrinkResources = true
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_26; targetCompatibility = JavaVersion.VERSION_26 }
}
kotlin { jvmToolchain(27); compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_26) } }
dependencies {
    implementation(project(":session-core"))
    implementation(libs.serializationJson)
    implementation(libs.androidxBrowser)
    implementation(libs.androidxLifecycleRuntimeCompose)
    implementation(libs.coroutinesAndroid)
    implementation(libs.androidxActivityCompose)
    implementation(platform(libs.composeBom))
    implementation(libs.composeUi); implementation(libs.composeFoundation); implementation(libs.composeMaterial3)
    androidTestImplementation(platform(libs.composeBom)); androidTestImplementation(libs.composeTestJunit4)
    androidTestImplementation(libs.androidxTestJunit); androidTestImplementation(libs.androidxTestRunner)
    androidTestImplementation(libs.espressoCore)
}
