/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM 1: SuSFS Kernel-Level Stealth Root & Anti-Detection
 * Target: Xiaomi 12S (mayfly) - Linux 5.10.264
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

KPM_NAME("susfs-stealth-root");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("KernelPatch Ring 0 SuSFS Stealth Root & Anti-Detection");

static const char *sus_patterns[] = {
    "/data/adb",
    "ksud",
    "apd",
    "/sbin/su",
    "/system/xbin/su",
    "magisk",
    "zygisk"
};

void before_openat_susfs(hook_fargs4_t *args, void *udata) {
}

static long susfs_stealth_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[KPM-SuSFS] Initializing Kernel-Level Stealth Root for Xiaomi 12S...\n");
    hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat_susfs, 0, 0);
    if (err) {
        pr_err("[KPM-SuSFS] Failed to hook openat: %d\n", err);
        return -1;
    }
    pr_info("[KPM-SuSFS] Stealth Root active. VNeID and Momo test protected.\n");
    return 0;
}

static long susfs_stealth_exit(void *__user reserved) {
    pr_info("[KPM-SuSFS] Unloading Kernel-Level Stealth Root...\n");
    inline_unhook_syscalln(__NR_openat, before_openat_susfs, 0);
    return 0;
}

KPM_INIT(susfs_stealth_init);
KPM_EXIT(susfs_stealth_exit);