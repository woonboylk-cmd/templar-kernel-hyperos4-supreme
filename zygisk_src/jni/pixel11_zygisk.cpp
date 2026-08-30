#include "zygisk.hpp"
#include <android/log.h>
#include <jni.h>
#include <string.h>
#include <string>
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
static const char *P_INCREMENTAL = "15938155";
static const char *P_SECURITY_PATCH = "2026-08-05";
static const char *P_SOC_MODEL = "Tensor G6";
static const char *P_SOC_MANUFACTURER = "Google";
static const char *P_TYPE = "user";
static const char *P_TAGS = "release-keys";
static const char *P_HOST = "r-36404f8caf3535e4-26ss";
static const char *P_USER = "android-build";

/* Camera Whitelist (Zero Touch - Always Protected) */
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

/* Match ALL Google Ecosystem Apps */
static bool is_target_app(const char *pkg) {
    if (!pkg) return false;
    if (strstr(pkg, "com.google.") || 
        strstr(pkg, "com.android.vending") ||
        strstr(pkg, "com.google.android.")) {
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
        set_static_string_field(env, build_class, "DISPLAY", P_ID);
        set_static_string_field(env, build_class, "HARDWARE", P_PRODUCT);
        set_static_string_field(env, build_class, "TYPE", P_TYPE);
        set_static_string_field(env, build_class, "TAGS", P_TAGS);
        set_static_string_field(env, build_class, "HOST", P_HOST);
        set_static_string_field(env, build_class, "USER", P_USER);
        set_static_string_field(env, build_class, "SOC_MODEL", P_SOC_MODEL);
        set_static_string_field(env, build_class, "SOC_MANUFACTURER", P_SOC_MANUFACTURER);
        env->DeleteLocalRef(build_class);
    } else {
        env->ExceptionClear();
    }

    jclass version_class = env->FindClass("android/os/Build$VERSION");
    if (version_class) {
        set_static_string_field(env, version_class, "SECURITY_PATCH", P_SECURITY_PATCH);
        set_static_string_field(env, version_class, "INCREMENTAL", P_INCREMENTAL);
        env->DeleteLocalRef(version_class);
    } else {
        env->ExceptionClear();
    }
}

/* PLT Hook for __system_property_get in native code */
static int (*orig_system_property_get)(const char *name, char *value) = nullptr;

static int my_system_property_get(const char *name, char *value) {
    if (!name || !value) return 0;

    if (strcmp(name, "ro.build.id") == 0 || strcmp(name, "ro.build.display.id") == 0) {
        strcpy(value, P_ID);
        return strlen(P_ID);
    }
    if (strcmp(name, "ro.product.model") == 0) {
        strcpy(value, P_MODEL);
        return strlen(P_MODEL);
    }
    if (strcmp(name, "ro.product.brand") == 0) {
        strcpy(value, P_BRAND);
        return strlen(P_BRAND);
    }
    if (strcmp(name, "ro.product.manufacturer") == 0) {
        strcpy(value, P_MANUFACTURER);
        return strlen(P_MANUFACTURER);
    }
    if (strcmp(name, "ro.product.name") == 0 || strcmp(name, "ro.product.device") == 0) {
        strcpy(value, P_PRODUCT);
        return strlen(P_PRODUCT);
    }
    if (strcmp(name, "ro.build.fingerprint") == 0) {
        strcpy(value, P_FINGERPRINT);
        return strlen(P_FINGERPRINT);
    }
    if (strcmp(name, "ro.build.version.incremental") == 0) {
        strcpy(value, P_INCREMENTAL);
        return strlen(P_INCREMENTAL);
    }
    if (strcmp(name, "ro.build.version.security_patch") == 0) {
        strcpy(value, P_SECURITY_PATCH);
        return strlen(P_SECURITY_PATCH);
    }
    if (strcmp(name, "ro.soc.model") == 0) {
        strcpy(value, P_SOC_MODEL);
        return strlen(P_SOC_MODEL);
    }

    if (orig_system_property_get) {
        return orig_system_property_get(name, value);
    }
    return __system_property_get(name, value);
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
                LOGI("Target Google app detected: %s -> Enforcing Pixel 11 Pro XL (CD1A.260714.001.A9)", process_name);

                if (api && api->pltHookRegister) {
                    api->pltHookRegister(".*", "__system_property_get", (void *)my_system_property_get, (void **)&orig_system_property_get);
                }
            }
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (enable_spoof && env) {
            if (api && api->pltHookCommit) {
                api->pltHookCommit();
            }
            spoof_build_fields(env);
            LOGI("Build fields & native properties locked to Pixel 11 Pro XL (CD1A.260714.001.A9) successfully.");
        }
    }

private:
    zygisk::ApiTable *api = nullptr;
    JNIEnv *env = nullptr;
    bool enable_spoof = false;
};

REGISTER_ZYGISK_MODULE(Pixel11ZygiskModule)