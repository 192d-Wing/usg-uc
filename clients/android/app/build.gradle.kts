import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.usg.sipclient"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.usg.sipclient"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        // The Rust core ships only arm64-v8a (devices) and x86_64 (emulator);
        // do not let Gradle package empty splits for other ABIs.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        debug {
            // BuildConfig.DEBUG is true; enables the gitignored DevSeed.json path.
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // The generated UniFFI bindings + JNA pull in duplicate license metadata.
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.material3:material3")

    // UniFFI's generated Kotlin uses JNA to call into libclient_ffi.so.
    // The @aar artifact bundles the per-ABI native JNA dispatch libraries.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // Coroutines are referenced by the generated UniFFI bindings (async runtime
    // glue) and by AppViewModel for the FFI-off-main-thread contract.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
