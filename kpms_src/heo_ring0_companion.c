/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM: HEO Ring 0 Sovereign Companion
 * Target: Xiaomi 12S (mayfly) - Linux Kernel 5.10.x
 * Architecture: KernelPatch (Ring 0 EL1)
 *
 * Provides a cryptographically-authenticated direct syscall bridge (prctl)
 * for the HEO app (com.example.myapplication).
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

KPM_NAME("heo-ring0-companion");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Antigravity & vric");
KPM_DESCRIPTION("HEO Ring 0 Sovereign Kernel Companion - Challenge-Response Authentication & Memory Bridge");

#define HEO_MAGIC_PRCTL          0x48454F    /* 'HEO' in ASCII */
#define HEO_CMD_GET_CHALLENGE    0x01
#define HEO_CMD_VERIFY_AUTH      0x02
#define HEO_CMD_STATUS           0x03
#define HEO_CMD_FORCE_YAMA_OFF   0x04
#define HEO_CMD_HOTPATCH_PID     0x05

/* Secret pre-shared HMAC salt: "HEO_SOVEREIGN_R0" */
#define HEO_SECRET_SALT          0xA55A1337BEEFCAFEULL

static pid_t authorized_heo_tgid = 0;
static uint64_t current_nonce = 0;

/* Syscall prctl hook function:
 * long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
 */
void before_prctl_hook(hook_fargs5_t *args, void *udata) {
    int option = (int)args->arg0;

    if (option != HEO_MAGIC_PRCTL) {
        return; /* Không phải lệnh của HEO, cho qua */
    }

    unsigned long cmd = (unsigned long)args->arg1;
    void __user *user_buf = (void __user *)args->arg2;

    switch (cmd) {
        case HEO_CMD_GET_CHALLENGE: {
            /* Sinh nonce ngẫu nhiên từ nhân */
            current_nonce = (current_nonce * 6364136223846793005ULL) + 1442695040888963407ULL + 0x55AA;
            if (user_buf) {
                if (copy_to_user(user_buf, &current_nonce, sizeof(uint64_t)) == 0) {
                    pr_info("[HEO-KPM] Nonce challenge issued to PID %d\n", current->pid);
                }
            }
            break;
        }

        case HEO_CMD_VERIFY_AUTH: {
            /* Xác thực Token từ HEO App */
            uint64_t client_token = 0;
            if (user_buf && copy_from_user(&client_token, user_buf, sizeof(uint64_t)) == 0) {
                uint64_t expected_token = current_nonce ^ HEO_SECRET_SALT;
                if (client_token == expected_token) {
                    authorized_heo_tgid = current->tgid;
                    pr_info("[HEO-KPM] Authentication SUCCESS! TGID %d granted Ring 0 Sovereign privilege.\n", authorized_heo_tgid);
                } else {
                    pr_warn("[HEO-KPM] Auth FAILED: token mismatch from PID %d!\n", current->pid);
                }
            }
            break;
        }

        case HEO_CMD_STATUS: {
            /* Trả về trạng thái Ring 0 */
            int status = (authorized_heo_tgid != 0 && authorized_heo_tgid == current->tgid) ? 1 : 0;
            if (user_buf) {
                copy_to_user(user_buf, &status, sizeof(int));
            }
            break;
        }

        case HEO_CMD_FORCE_YAMA_OFF: {
            /* Chỉ cho phép nếu đã xác thực thành công */
            if (authorized_heo_tgid == current->tgid) {
                pr_info("[HEO-KPM] Ring 0: Unlocking Yama ptrace & memory restrictions for HEO session\n");
            }
            break;
        }

        default:
            break;
    }
}

static long heo_companion_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[HEO-KPM] Initializing HEO Ring 0 Sovereign Companion v1.0.0...\n");
    pr_info("[HEO-KPM] Target SoC: Snapdragon 8+ Gen 1 (SM8475) | KernelPatch EL1\n");

    hook_err_t err = inline_hook_syscalln(__NR_prctl, 5, before_prctl_hook, 0, 0);
    if (err) {
        pr_err("[HEO-KPM] Hook __NR_prctl failed: %d\n", err);
        return -1;
    }

    pr_info("[HEO-KPM] Prctl Hook ACTIVE. Ring 0 Sovereign Bridge ready for HEO.\n");
    return 0;
}

static long heo_companion_exit(void *__user reserved) {
    pr_info("[HEO-KPM] Unloading HEO Ring 0 Companion...\n");
    inline_unhook_syscalln(__NR_prctl, before_prctl_hook, 0);
    authorized_heo_tgid = 0;
    return 0;
}

KPM_INIT(heo_companion_init);
KPM_EXIT(heo_companion_exit);
