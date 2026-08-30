#include "zygisk.hpp"
#include <android/log.h>
#include <jni.h>
#include <string.h>
#include <string>
#include <vector>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <unistd.h>

#define LOG_TAG "Pixel11Spoofer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* Kodiak Pixel 11 Pro XL Identity Data */
static const char *P_MODEL = "Pixel 11 Pro XL";
static const char *P_BRAND = "google";
static const char *P_MANUFACTURER = "Google";
static const char *P_PRODUCT = "kodiak";
static const char *P_DEVICE = "kodiak";
static const char *P_FINGERPRINT = "google/kodiak/kodiak:17/CD1A.260714.001.A9/15938155:user/release-keys";
static const char *P_ID = "CD1A.260714.001.A9";
static const char *P_SECURITY_PATCH = "2026-08-05";
static const char *P_SOC_MODEL = "Tensor G6";
static const char *P_SOC_MANUFACTURER = "Google";

/* Camera Whitelist (Zero Touch) */
static const char *camera_whitelist[] = {
    "com.android.camera",
    "com.xiaomi.vtcamera",
    "vendor.qti.camera",
    "cameraserver",
    "com.miui.gallery",
    "miui"
};

static bool is_whitelisted_camera(const char *pkg) {
    if (!pkg) return false;
    for (size_t i = 0; i < sizeof(camera_whitelist) / sizeof(camera_whitelist[0]); i++) {
        if (strstr(pkg, camera_whitelist[i])) {
            return true;
        }
    }
    return false;
}

static bool is_target_app(const char *pkg) {
    if (!pkg) return false;
    if (strstr(pkg, "com.google.android.apps.photos") ||
        strstr(pkg, "com.google.android.gms") ||
        strstr(pkg, "com.google.android.gsf") ||
        strstr(pkg, "com.google.android.googlequicksearchbox") ||
        strstr(pkg, "com.google.android.apps.bard") ||
        strstr(pkg, "com.google.android.apps.gemini")) {
        return true;
    }
    return false;
}

static void set_static_string_field(JNIEnv *env, jclass clazz, const char *field_name, const char *value) {
    if (!clazz || !field_name || !value) return;
    jfieldID fid = env->GetStaticFieldID(clazz, field_name, "Ljava/lang/String;");
    if (fid) {
        jstring jval = env->NewStringUTF(value);
        env->SetStaticObjectField(clazz, fid, jval);
        env->DeleteLocalRef(jval);
    } else {
        env->ExceptionClear();
    }
}

static void spoof_build_fields(JNIEnv *env) {
    if (!env) return;

    jclass build_class = env->FindClass("android/os/Build");
    if (build_class) {
        set_static_string_field(env, build_class, "MODEL", P_MODEL);
        set_static_string_field(env, build_class, "BRAND", P_BRAND);
        set_static_string_field(env, build_class, "MANUFACTURER", P_MANUFACTURER);
        set_static_string_field(env, build_class, "PRODUCT", P_PRODUCT);
        set_static_string_field(env, build_class, "DEVICE", P_DEVICE);
        set_static_string_field(env, build_class, "FINGERPRINT", P_FINGERPRINT);
        set_static_string_field(env, build_class, "ID", P_ID);
        set_static_string_field(env, build_class, "HARDWARE", P_PRODUCT);
        set_static_string_field(env, build_class, "SOC_MODEL", P_SOC_MODEL);
        set_static_string_field(env, build_class, "SOC_MANUFACTURER", P_SOC_MANUFACTURER);
        env->DeleteLocalRef(build_class);
    } else {
        env->ExceptionClear();
    }

    jclass version_class = env->FindClass("android/os/Build$VERSION");
    if (version_class) {
        set_static_string_field(env, version_class, "SECURITY_PATCH", P_SECURITY_PATCH);
        env->DeleteLocalRef(version_class);
    } else {
        env->ExceptionClear();
    }
}

class Pixel11ZygiskModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::ApiTable *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *process_name = nullptr;
        if (args->nice_name) {
            process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        }

        if (process_name) {
            if (is_whitelisted_camera(process_name)) {
                enable_spoof = false;
            } else if (is_target_app(process_name)) {
                enable_spoof = true;
                LOGI("Target detected: %s -> Spoofing Pixel 11 Pro XL (Kodiak)", process_name);
            }
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (enable_spoof && env) {
            spoof_build_fields(env);
            LOGI("Build fields spoofed to Pixel 11 Pro XL successfully.");
        }
    }

private:
    zygisk::ApiTable *api = nullptr;
    JNIEnv *env = nullptr;
    bool enable_spoof = false;
};

REGISTER_ZYGISK_MODULE(Pixel11ZygiskModule)