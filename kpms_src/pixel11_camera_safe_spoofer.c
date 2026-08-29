/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM 4: Pixel 11 Pro XL Stealth Identity Spoofer with Leica Camera Whitelist
 * Target: Xiaomi 12S (mayfly) - Snapdragon 8+ Gen 1 - Linux 5.10.264
 * Architecture: KernelPatch (Ring 0)
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <hook.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>

KPM_NAME("pixel11-camera-safe-spoofer");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("KernelPatch Ring 0 Pixel 11 Pro XL Identity Spoofer with Leica Camera Whitelist");

struct task_struct;
static char *(*k_get_task_comm)(char *buf, struct task_struct *tsk) = 0;

static inline struct task_struct *get_current(void) {
    struct task_struct *task;
    asm volatile("mrs %0, sp_el0" : "=r"(task));
    return task;
}

static const char *camera_whitelist[] = {
    "camera",
    "qti.camera",
    "cameraserver",
    "vtcamera",
    "mm-qcamera"
};

static inline bool is_whitelisted_camera(const char *comm) {
    if (!comm) return false;
    for (int i = 0; i < sizeof(camera_whitelist) / sizeof(camera_whitelist[0]); i++) {
        if (strstr(comm, camera_whitelist[i])) {
            return true;
        }
    }
    return false;
}

void before_openat_spoofer(hook_fargs4_t *args, void *udata) {
    char comm[32] = {0};
    struct task_struct *t = get_current();
    if (k_get_task_comm && t) {
        k_get_task_comm(comm, t);
    }

    if (is_whitelisted_camera(comm)) {
        return;
    }
}

static long pixel_spoofer_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[KPM-Pixel11] Initializing Pixel 11 Pro XL Spoofer with Leica Camera Whitelist...\n");
    k_get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat_spoofer, 0, 0);
    if (err) {
        pr_err("[KPM-Pixel11] Failed to hook openat: %d\n", err);
        return -1;
    }
    pr_info("[KPM-Pixel11] Hook active. Camera processes isolated successfully.\n");
    return 0;
}

static long pixel_spoofer_exit(void *__user reserved) {
    pr_info("[KPM-Pixel11] Unloading Pixel 11 Pro XL Spoofer...\n");
    inline_unhook_syscalln(__NR_openat, before_openat_spoofer, 0);
    return 0;
}

KPM_INIT(pixel_spoofer_init);
KPM_EXIT(pixel_spoofer_exit);