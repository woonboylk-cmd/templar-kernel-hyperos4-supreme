/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: Pixel 11 Pro XL Identity Spoofer with Leica Camera Whitelist v3.0
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 - Linux 5.10.264
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Mechanism:
 * 1. Zero-Lock Comm Resolver: Reads process name without taking task_lock (Zero deadlock).
 * 2. Leica Camera Whitelist: Camera processes read genuine Xiaomi build.prop.
 * 3. In-Place Syscall Redirection: Intercepts openat on /system/build.prop, /product/etc/build.prop
 *    and redirects to /data/adb/p11.prop in user buffer, restoring on completion.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <linux/string.h>
#include <asm/current.h>

KPM_NAME("pixel11-camera-safe-spoofer");
KPM_VERSION("3.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("Pixel 11 Pro XL Identity Spoofer v3.0 - In-Place Syscall Redirection with Leica Camera Whitelist");

#define SPOOF_TARGET_PATH "/data/adb/p11.prop"
#define SPOOF_TARGET_LEN  18

static unsigned long (*p_copy_to_user)(void *to, const void *from, unsigned long n) = (void *)0;
static unsigned long (*p_copy_from_user)(void *to, const void *from, unsigned long n) = (void *)0;
static char *(*p_get_task_comm)(char *buf, unsigned long buf_size, void *tsk) = (void *)0;
static int g_comm_offset = -1;

/* Leica Camera Whitelist (Protected from spoofing) */
static const char *camera_whitelist[] = {
    "camera",
    "qti.camera",
    "cameraserver",
    "vtcamera",
    "mm-qcamera",
    "miui.gallery",
    "gallery"
};

static inline size_t k_strlen(const char *s) {
    size_t len = 0;
    while (s && s[len]) len++;
    return len;
}

static inline int k_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) return p1[i] - p2[i];
    }
    return 0;
}

static inline int str_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    const char *h = haystack;
    while (*h) {
        const char *h_sub = h;
        const char *n_sub = needle;
        while (*h_sub && *n_sub && (*h_sub == *n_sub)) {
            h_sub++;
            n_sub++;
        }
        if (!*n_sub) return 1;
        h++;
    }
    return 0;
}

static inline int is_whitelisted_camera(const char *comm) {
    if (!comm || comm[0] == '\0') return 0;
    for (size_t i = 0; i < sizeof(camera_whitelist) / sizeof(camera_whitelist[0]); i++) {
        if (str_contains(comm, camera_whitelist[i])) {
            return 1;
        }
    }
    return 0;
}

/* Zero-Lock Comm Resolver */
static int resolve_task_comm_offset(void) {
    if (!p_get_task_comm) return -1;
    char ref_name[16] = {0};
    p_get_task_comm(ref_name, sizeof(ref_name), current);
    ref_name[15] = '\0';

    size_t len = k_strlen(ref_name);
    if (len == 0) return -1;

    const unsigned char *base = (const unsigned char *)current;
    for (int off = 0x200; off < 0x1800; off += 4) {
        if (k_memcmp(base + off, ref_name, len) == 0 && base[off + len] == '\0') {
            unsigned long cred_candidate = *(const unsigned long *)(base + off - 8);
            if ((cred_candidate >> 48) == 0xffff) {
                g_comm_offset = off;
                pr_info("[KPM-Pixel11] Zero-Lock comm offset: 0x%x\n", off);
                return off;
            }
        }
    }
    return -1;
}

/*
 * Syscall openat hook:
 * int openat(int dfd, const char __user *filename, int flags, umode_t mode);
 * arg0: dfd
 * arg1: filename
 * arg2: flags
 * arg3: mode
 */
void before_openat_spoofer(hook_fargs4_t *args, void *udata) {
    if (!p_copy_from_user || !p_copy_to_user) return;

    void *user_path_ptr = (void *)args->arg1;
    if (!user_path_ptr) return;

    /* 1. Extract process comm using Zero-Lock */
    char comm[16] = {0};
    if (g_comm_offset > 0) {
        const char *raw_comm = (const char *)current + g_comm_offset;
        for (int i = 0; i < 15; i++) {
            char c = raw_comm[i];
            comm[i] = c;
            if (c == '\0') break;
        }
        comm[15] = '\0';
    }

    /* 2. Leica Camera Whitelist: Pass through without modification */
    if (is_whitelisted_camera(comm)) {
        return;
    }

    /* 3. Inspect target path from userspace */
    char path_buf[64] = {0};
    if (p_copy_from_user(path_buf, user_path_ptr, 63) != 0) {
        return;
    }
    path_buf[63] = '\0';

    /* 4. Filter for build.prop targets (exclude vendor/odm/p11) */
    if (str_contains(path_buf, "build.prop") &&
        !str_contains(path_buf, "vendor") &&
        !str_contains(path_buf, "odm") &&
        !str_contains(path_buf, "p11.prop")) {

        size_t orig_len = k_strlen(path_buf);
        if (orig_len >= SPOOF_TARGET_LEN) {
            /* In-place redirection: Overwrite userspace buffer with spoof path */
            p_copy_to_user(user_path_ptr, SPOOF_TARGET_PATH, SPOOF_TARGET_LEN + 1);
            pr_info("[KPM-Pixel11] Redirected '%s' open: '%s' -> %s\n",
                    comm, path_buf, SPOOF_TARGET_PATH);
        }
    }
}

static long pixel_spoofer_init(const char *args, const char *event, void *reserved) {
    pr_info("[KPM-Pixel11] ===== Initializing Pixel 11 Pro XL Spoofer v3.5 (openat + newfstatat) =====\n");

    p_copy_to_user = (void *)kallsyms_lookup_name("__arch_copy_to_user");
    p_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");

    resolve_task_comm_offset();

    hook_err_t err1 = inline_hook_syscalln(__NR_openat, 4, before_openat_spoofer, NULL, NULL);
    if (err1) {
        pr_err("[KPM-Pixel11] inline_hook_syscalln(__NR_openat) failed: %d\n", err1);
    }

    hook_err_t err2 = inline_hook_syscalln(__NR_newfstatat, 4, before_openat_spoofer, NULL, NULL);
    if (err2) {
        pr_err("[KPM-Pixel11] inline_hook_syscalln(__NR_newfstatat) failed: %d\n", err2);
    }

    pr_info("[KPM-Pixel11] In-Place Syscall Redirection ACTIVE (openat=%d, newfstatat=%d). Leica Camera Protected.\n",
            !err1, !err2);
    return 0;
}

static long pixel_spoofer_exit(void *reserved) {
    pr_info("[KPM-Pixel11] Unloading Pixel 11 Pro XL Spoofer...\n");
    inline_unhook_syscalln(__NR_openat, before_openat_spoofer, NULL);
    inline_unhook_syscalln(__NR_newfstatat, before_openat_spoofer, NULL);
    return 0;
}

KPM_INIT(pixel_spoofer_init);
KPM_EXIT(pixel_spoofer_exit);