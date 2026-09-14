/**
 * Pixel 11 Pro XL Identity Engine & HEO Sovereign Zygote Tamer v3.5
 *
 * Capabilities:
 * 1. Pixel 11 Pro XL Identity Spoofing for Google Ecosystem & Photos
 * 2. Zero-touch Camera Whitelist protection (Leica / Xiaomi Camera Safe)
 * 3. HEO Sovereign Zygote Tamer:
 *    - DEMOTE: Pin to LITTLE cores 0-3 (Cortex-A510) and set Nice 19
 *    - BOOST: Pin to MID/PRIME cores 4-7 (Cortex-A710/X2) and set Nice -10
 *    - BLOCK: Immediately terminate at fork (_exit(0)) before ART initializes
 *
 * Copyright (c) 2026 vric & Antigravity. Sovereign Constitution Compliant.
 */

#define _GNU_SOURCE
#include "zygisk.hpp"
#include <android/log.h>
#include <jni.h>
#include <string.h>
#include <strings.h>
#include <string>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

/* Protected apps that must NEVER be tamed or blocked */
static bool is_protected_app(const char *pkg) {
    if (!pkg) return true;
    if (strcmp(pkg, "com.example.myapplication") == 0) return true;
    if (strcmp(pkg, "android") == 0) return true;
    if (strstr(pkg, "systemui")) return true;
    if (strstr(pkg, "camera")) return true;
    if (strstr(pkg, "cameraserver")) return true;
    if (strstr(pkg, "gallery")) return true;
    if (strstr(pkg, "apatch")) return true;
    if (strstr(pkg, "ksu")) return true;
    if (strstr(pkg, "magisk")) return true;
    return false;
}

enum class TamerAction {
    NONE,
    DEMOTE,
    BOOST,
    BLOCK
};

static TamerAction evaluate_tamer_rule(const char *process_name) {
    if (!process_name || is_protected_app(process_name)) return TamerAction::NONE;

    const char *paths[] = {
        "/data/adb/heo/tamer_rules.txt",
        "/data/local/tmp/heo_tamer.txt"
    };

    FILE *fp = nullptr;
    for (const char *p : paths) {
        fp = fopen(p, "re");
        if (fp) break;
    }
    if (!fp) return TamerAction::NONE;

    char line[512];
    TamerAction matched_action = TamerAction::NONE;

    while (fgets(line, sizeof(line), fp)) {
        char *ptr = line;
        while (*ptr == ' ' || *ptr == '\t') ptr++;
        if (*ptr == '#' || *ptr == '\r' || *ptr == '\n' || *ptr == '\0') continue;

        char *colon = strchr(ptr, ':');
        if (!colon) continue;

        *colon = '\0';
        char *target_pkg = ptr;
        char *action_str = colon + 1;

        char *end = target_pkg + strlen(target_pkg) - 1;
        while (end > target_pkg && (*end == ' ' || *end == '\t')) *end-- = '\0';

        while (*action_str == ' ' || *action_str == '\t') action_str++;
        char *act_end = action_str + strlen(action_str) - 1;
        while (act_end >= action_str && (*act_end == ' ' || *act_end == '\t' || *act_end == '\r' || *act_end == '\n')) *act_end-- = '\0';

        if (strcmp(process_name, target_pkg) == 0 || strstr(process_name, target_pkg) != nullptr) {
            if (strcasecmp(action_str, "DEMOTE") == 0) {
                matched_action = TamerAction::DEMOTE;
                break;
            } else if (strcasecmp(action_str, "BOOST") == 0) {
                matched_action = TamerAction::BOOST;
                break;
            } else if (strcasecmp(action_str, "BLOCK") == 0) {
                matched_action = TamerAction::BLOCK;
                break;
            }
        }
    }

    fclose(fp);
    return matched_action;
}

static void apply_tamer_action(const char *process_name, TamerAction action) {
    if (action == TamerAction::DEMOTE) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset);
        CPU_SET(1, &cpuset);
        CPU_SET(2, &cpuset);
        CPU_SET(3, &cpuset);
        if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0) {
            LOGI("[ZygoteTamer] DEMOTE enforced on %s: Pinned to LITTLE cores 0-3 (Cortex-A510)", process_name);
        } else {
            LOGE("[ZygoteTamer] sched_setaffinity DEMOTE failed for %s: %s", process_name, strerror(errno));
        }
        if (setpriority(PRIO_PROCESS, 0, 19) == 0) {
            LOGI("[ZygoteTamer] DEMOTE enforced on %s: Nice set to 19 (idle priority)", process_name);
        }
    } else if (action == TamerAction::BOOST) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(4, &cpuset);
        CPU_SET(5, &cpuset);
        CPU_SET(6, &cpuset);
        CPU_SET(7, &cpuset);
        if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0) {
            LOGI("[ZygoteTamer] BOOST enforced on %s: Pinned to MID/PRIME cores 4-7 (Cortex-A710/X2)", process_name);
        } else {
            LOGE("[ZygoteTamer] sched_setaffinity BOOST failed for %s: %s", process_name, strerror(errno));
        }
        if (setpriority(PRIO_PROCESS, 0, -10) == 0) {
            LOGI("[ZygoteTamer] BOOST enforced on %s: Nice set to -10 (high priority)", process_name);
        }
    } else if (action == TamerAction::BLOCK) {
        LOGI("[ZygoteTamer] BLOCK enforced on %s: Terminating process immediately before ART init", process_name);
        _exit(0);
    }
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
            // 1. HEO Zygote Tamer Enforcement (runs for any matched app at fork)
            TamerAction act = evaluate_tamer_rule(process_name);
            if (act != TamerAction::NONE) {
                apply_tamer_action(process_name, act);
            }

            // 2. Pixel 11 Pro XL Identity Engine
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
        (void)args;
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
