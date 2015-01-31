#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <mach/mach.h>
#include <mach/mig.h>

#include <bits/syscall.h>
#include <asm-generic/errno.h>

#ifndef NDEBUG
#define DEBUG(fmt, ...) fprintf(stderr, "d: %s: " fmt "\n", __func__, __VA_ARGS__)
#define PFAIL(reason) do { pfail(__func__, reason); goto fail; } while(0)
#define FAIL(reason, retval) do { fail(__func__, reason, retval); goto fail; } while(0)
#define XFAIL(reason, retval) fail(__func__, "cleanup:" reason, retval)
#define ASSERT(reason, retval) do { fail(__func__, reason, retval); abort(); } while(0)
#else
#define DEBUG(...) do ; while(0)
#define PFAIL(reason) goto fail
#define FAIL(reason, retval) goto fail
#define XFAIL(reason, retval) do ; while(0)
#define ASSERT(reason, retval) do ; while(0)
#endif

#define PRINT_STATE(state) \
        do { \
            DEBUG("RAX %016llx R8  %016llx", (state).__rax, (state).__r8); \
            DEBUG("RBX %016llx R9  %016llx", (state).__rbx, (state).__r9); \
            DEBUG("RCX %016llx R10 %016llx", (state).__rcx, (state).__r10); \
            DEBUG("RDX %016llx R11 %016llx", (state).__rdx, (state).__r11); \
            DEBUG("RDI %016llx R12 %016llx", (state).__rdi, (state).__r12); \
            DEBUG("RSI %016llx R13 %016llx", (state).__rsi, (state).__r13); \
            DEBUG("RBP %016llx R14 %016llx", (state).__rbp, (state).__r14); \
            DEBUG("RSP %016llx R15 %016llx", (state).__rsp, (state).__r15); \
            DEBUG("CS:RIP %04x:%016llx FS %04x GS %04x", \
                  (uint16_t) (state).__cs, (state).__rip, \
                  (uint16_t) (state).__fs, (uint16_t) (state).__gs); \
            DEBUG("RFLAGS %016llx", (state).__rflags); \
        } while(0)

static void pfail(const char *fn, const char *reason) {
        fprintf(stderr, "e: %s: %s\n", fn, reason);
}

static void fail(const char *fn, const char *reason, kern_return_t retval) {
        fprintf(stderr, "e: %s: %s: %08x %s\n", fn, reason, retval, mach_error_string(retval));
}

/* do the port swap dance in newly forked task */
static void emu_spawn_helper() {
        kern_return_t retval;

        mach_port_t send;
        if((retval = task_get_bootstrap_port(mach_task_self(), &send)))
                FAIL("task_get_bootstrap_port", retval);

        mach_port_t reply;
        if((retval = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply)))
                FAIL("mach_port_allocate", retval);

        // DEBUG("send %d reply %d", send, reply);

        /* send reply port and self rights */
        struct {
                mach_msg_header_t hdr;
                mach_msg_body_t body;
                mach_msg_port_descriptor_t task_port;
        } task_msg = {{0}};
        task_msg.hdr.msgh_size = sizeof(task_msg);
        task_msg.hdr.msgh_bits =
                MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND) |
                MACH_MSGH_BITS_COMPLEX;
        task_msg.hdr.msgh_remote_port = send;
        task_msg.hdr.msgh_local_port = reply;
        task_msg.body.msgh_descriptor_count = 1;
        task_msg.task_port.name = mach_task_self();
        task_msg.task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
        task_msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;
        if((retval = mach_msg_send(&task_msg.hdr)))
                FAIL("mach_msg_send", retval);

        /* receive old bootstrap port */
        struct {
                mach_msg_header_t hdr;
                mach_msg_trailer_t trail;
        } bootstrap_msg = {{0}};
        bootstrap_msg.hdr.msgh_size = sizeof(bootstrap_msg);
        bootstrap_msg.hdr.msgh_local_port = reply;
        if((retval = mach_msg_receive(&bootstrap_msg.hdr)))
                FAIL("mach_msg_receive:bootstrap", retval);

        mach_port_t old_bootstrap = bootstrap_msg.hdr.msgh_remote_port;
        // DEBUG("bootstrap %d", old_bootstrap);

        if((retval = task_set_bootstrap_port(mach_task_self(), old_bootstrap)))
                FAIL("task_set_bootstrap_port", retval);

        if((retval = thread_suspend(mach_thread_self())))
                FAIL("thread_suspend", retval);

        char *argv[] = {"./linux", NULL}, *envp[] = {NULL};
        if(execve("./app", argv, envp))
                perror("execve");

fail:
        exit(1);
}

/* spawn a new suspended task */
static kern_return_t emu_spawn(mach_port_t *task) {
        kern_return_t retval, xretval;
        mach_port_t recv = 0, send = 0, reply = 0, child = 0;
        mach_msg_type_name_t type;

        if((retval = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv)))
                FAIL("mach_port_allocate", retval);

        if((retval = mach_port_extract_right(mach_task_self(),
                        recv, MACH_MSG_TYPE_MAKE_SEND, &send, &type)))
                FAIL("mach_port_extract_right", retval);

        // DEBUG("recv %d send %d type 0x%x", recv, send, type);

        mach_port_t old_bootstrap = 0;
        if((retval = task_get_bootstrap_port(mach_task_self(), &old_bootstrap)))
                FAIL("task_get_bootstrap_port", retval);

        if((retval = task_set_bootstrap_port(mach_task_self(), send)))
                FAIL("task_set_bootstrap_port", retval);

        pid_t pid;
        if(!(pid = fork()))
                emu_spawn_helper();

        DEBUG("pid %d", pid);

        if((retval = task_set_bootstrap_port(mach_task_self(), old_bootstrap)))
                FAIL("task_set_bootstrap_port", retval);

        struct {
                mach_msg_header_t hdr;
                mach_msg_body_t body;
                mach_msg_port_descriptor_t task_port;
                mach_msg_trailer_t trail;
        } task_msg = {{0}};
        task_msg.hdr.msgh_size = sizeof(task_msg);
        task_msg.hdr.msgh_local_port = recv;
        if((retval = mach_msg_receive(&task_msg.hdr)))
                FAIL("mach_msg_receive:task", retval);

        reply = task_msg.hdr.msgh_remote_port;
        child = task_msg.task_port.name;
        //DEBUG("got reply %d task %d", reply, child);

        mach_msg_header_t bootstrap_msg = {0};
        bootstrap_msg.msgh_size = sizeof(bootstrap_msg);
        bootstrap_msg.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND);
        bootstrap_msg.msgh_remote_port = reply;
        bootstrap_msg.msgh_local_port = old_bootstrap;
        if((retval = mach_msg_send(&bootstrap_msg)))
                FAIL("mach_msg_send:bootstrap", retval);

        *task = child;

fail:
        if(retval) {
                if(child && (xretval = mach_port_deallocate(mach_task_self(), child)))
                        XFAIL("mach_port_deallocate:child", xretval);
        }

        if(recv && (xretval = mach_port_deallocate(mach_task_self(), recv)))
                XFAIL("mach_port_deallocate:recv", xretval);

        if(reply && (xretval = mach_port_deallocate(mach_task_self(), reply)))
                XFAIL("mach_port_deallocate:reply", xretval);

        return retval;
}

static kern_return_t emu_spawn_task(mach_port_t exn_set) {
        kern_return_t retval, xretval;
        mach_port_t task = 0, syscall = 0, syscall_send = 0;
        mach_msg_type_name_t type;
        thread_array_t threads = NULL;
        mach_msg_type_number_t thread_count;

        if((retval = emu_spawn(&task)))
                FAIL("emu_spawn", retval);

        if((retval = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &syscall)))
                FAIL("mach_port_allocate", retval);

        //DEBUG("syscall port %d", syscall);

        if((retval = mach_port_extract_right(mach_task_self(),
                        syscall, MACH_MSG_TYPE_MAKE_SEND, &syscall_send, &type)))
                FAIL("mach_port_extract_right", retval);

        if((retval = mach_port_move_member(mach_task_self(), syscall, exn_set)))
                FAIL("mach_port_move_member", retval);

        if((retval = task_set_exception_ports(task,
                        EXC_MASK_ALL, syscall_send,
                        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, x86_THREAD_STATE64)))
                FAIL("task_set_exception_ports", retval);

        if((retval = task_threads(task, &threads, &thread_count)))
                FAIL("task_threads", retval);

        //DEBUG("%d threads", thread_count);

        usleep(1000);
        if((retval = thread_resume(threads[0])))
                FAIL("thread_resume", retval);

fail:
        if(retval) {
                if(task && (xretval = mach_port_deallocate(mach_task_self(), task)))
                        XFAIL("mach_port_deallocate:task", xretval);
        }

        if(threads && (xretval = vm_deallocate(mach_task_self(),
                        (vm_address_t) threads, sizeof(thread_t) * thread_count)))
                XFAIL("vm_deallocate:threads", xretval);

        return retval;
}

#define SYSCALL_SUSPEND 0x7fffffffffffffff

typedef struct {
        mach_port_t sysret_port;
        mach_port_t task;
        mach_port_t thread;
} syscall_context_t;

static void emu_syscall_return(syscall_context_t *context, uint64_t syscall_retval,
                               x86_thread_state64_t *state);
static void emu_syscall_return_nostate(syscall_context_t *context,
                                       uint64_t syscall_retval);

static inline void* emu_map(syscall_context_t *context,
                            uint64_t ptr, uint64_t len, vm_prot_t prot) {
        kern_return_t retval;
        void *out = NULL;
        vm_prot_t cur, max;
        if((retval = vm_remap(mach_task_self(), (vm_address_t*) &out, (vm_size_t) len,
                        (vm_address_t) 0, TRUE, context->task, (vm_address_t) ptr,
                        FALSE, &cur, &max, VM_INHERIT_NONE)))
                FAIL("vm_remap", retval);

        if(!(cur & prot)) {
                if(prot & VM_PROT_WRITE)
                        PFAIL("perm:rw");
                else
                        PFAIL("perm:ro");
        }

        return out;

fail:   return NULL;
}

static inline void* emu_map_rw(syscall_context_t *context, uint64_t ptr, uint64_t len) {
        return emu_map(context, ptr, len, VM_PROT_READ | VM_PROT_WRITE);
}

static inline const void* emu_map_ro(syscall_context_t *context, uint64_t ptr, uint64_t len) {
        return emu_map(context, ptr, len, VM_PROT_READ);
}

static inline void emu_unmap(syscall_context_t *context, const void *obj, uint64_t len) {
        kern_return_t retval;
        if((retval = vm_deallocate(mach_task_self(), (vm_address_t) obj, (vm_size_t) len)))
                ASSERT("vm_deallocate", retval);
}

static inline int emu_ret(int ret) {
        if(ret >= 0) return ret;

        switch(ret) {
        default: fail(__func__, "unknown errno %d\n", -ret); return -EIO;
#define ERRNO(x) case -x: return -linux_ ## x;
        ERRNO(EPERM)
        ERRNO(ENOENT)
        ERRNO(ESRCH)
        ERRNO(EINTR)
        ERRNO(EIO)
        ERRNO(ENXIO)
        ERRNO(E2BIG)
        ERRNO(ENOEXEC)
        ERRNO(EBADF)
        ERRNO(ECHILD)
        ERRNO(EDEADLK)
        ERRNO(ENOMEM)
        ERRNO(EACCES)
        ERRNO(EFAULT)
        ERRNO(ENOTBLK)
        ERRNO(EBUSY)
        ERRNO(EEXIST)
        ERRNO(EXDEV)
        ERRNO(ENODEV)
        ERRNO(ENOTDIR)
        ERRNO(EISDIR)
        ERRNO(EINVAL)
        ERRNO(ENFILE)
        ERRNO(EMFILE)
        ERRNO(ENOTTY)
        ERRNO(ETXTBSY)
        ERRNO(EFBIG)
        ERRNO(ENOSPC)
        ERRNO(ESPIPE)
        ERRNO(EROFS)
        ERRNO(EMLINK)
        ERRNO(EPIPE)
        ERRNO(EDOM)
        ERRNO(ERANGE)
        ERRNO(EAGAIN)
        ERRNO(EINPROGRESS)
        ERRNO(EALREADY)
        ERRNO(ENOTSOCK)
        ERRNO(EDESTADDRREQ)
        ERRNO(EMSGSIZE)
        ERRNO(EPROTOTYPE)
        ERRNO(ENOPROTOOPT)
        ERRNO(EPROTONOSUPPORT)
        ERRNO(ESOCKTNOSUPPORT)
        //ERRNO(ENOTSUP)
        ERRNO(EOPNOTSUPP)
        ERRNO(EPFNOSUPPORT)
        ERRNO(EAFNOSUPPORT)
        ERRNO(EADDRINUSE)
        ERRNO(EADDRNOTAVAIL)
        ERRNO(ENETDOWN)
        ERRNO(ENETUNREACH)
        ERRNO(ENETRESET)
        ERRNO(ECONNABORTED)
        ERRNO(ECONNRESET)
        ERRNO(ENOBUFS)
        ERRNO(EISCONN)
        ERRNO(ENOTCONN)
        ERRNO(ESHUTDOWN)
        ERRNO(ETOOMANYREFS)
        ERRNO(ETIMEDOUT)
        ERRNO(ECONNREFUSED)
        ERRNO(ELOOP)
        ERRNO(ENAMETOOLONG)
        ERRNO(EHOSTDOWN)
        ERRNO(EHOSTUNREACH)
        ERRNO(ENOTEMPTY)
        //ERRNO(EPROCLIM)
        ERRNO(EUSERS)
        ERRNO(EDQUOT)
        ERRNO(ESTALE)
        ERRNO(EREMOTE)
        //ERRNO(EBADRPC)
        //ERRNO(ERPCMISMATCH)
        //ERRNO(EPROGUNAVAIL)
        //ERRNO(EPROGMISMATCH)
        //ERRNO(EPROCUNAVAIL)
        ERRNO(ENOLCK)
        ERRNO(ENOSYS)
        //ERRNO(EFTYPE)
        //ERRNO(EAUTH)
        //ERRNO(ENEEDAUTH)
        //ERRNO(EPWROFF)
        //ERRNO(EDEVERR)
        ERRNO(EOVERFLOW)
        //ERRNO(EBADEXEC)
        //ERRNO(EBADARCH)
        //ERRNO(ESHLIBVERS)
        //ERRNO(EBADMACHO)
        ERRNO(ECANCELED)
        ERRNO(EIDRM)
        ERRNO(ENOMSG)
        ERRNO(EILSEQ)
        //ERRNO(ENOATTR)
        ERRNO(EBADMSG)
        ERRNO(EMULTIHOP)
        ERRNO(ENODATA)
        ERRNO(ENOLINK)
        ERRNO(ENOSR)
        ERRNO(ENOSTR)
        ERRNO(EPROTO)
        ERRNO(ETIME)
        //ERRNO(ENOPOLICY)
        ERRNO(ENOTRECOVERABLE)
        ERRNO(EOWNERDEAD)
        //ERRNO(EQFULL)
#undef ERRNO
        }
}

static uint64_t emu_write(syscall_context_t *context,
                          uint64_t fd, uint64_t ptr, uint64_t len) {
        DEBUG("fd %lld ptr %016llx len %lld", fd, ptr, len);

        const void *obj;
        if(!(obj = emu_map_ro(context, ptr, len)))
                return -linux_EFAULT;

        int ret = emu_ret(write(fd, obj, len));

        emu_unmap(context, obj, len);

        return ret;
}

static uint64_t emu_exit(syscall_context_t *context,
                         uint64_t code) {
        DEBUG("code %lld", code);
        task_terminate(context->task);
        return SYSCALL_SUSPEND;
}

#define SYSCALL1(fn) \
        case __NR_ ## fn: retval = emu_ ## fn (context, \
                state->__rdi); break;
#define SYSCALL2(fn) \
        case __NR_ ## fn: retval = emu_ ## fn (context, \
                state->__rdi, state->__rsi); break;
#define SYSCALL3(fn) \
        case __NR_ ## fn: retval = emu_ ## fn (context, \
                state->__rdi, state->__rsi, state->__rdx); break;
#define SYSCALL4(fn) \
        case __NR_ ## fn: retval = emu_ ## fn (context, \
                state->__rdi, state->__rsi, state->__rdx, \
                state->__rcx); break;
#define SYSCALL5(fn) \
        case __NR_ ## fn: retval = emu_ ## fn (context, \
                state->__rdi, state->__rsi, state->__rdx, \
                state->__rcx, state->__r8); break;
#define SYSCALL6(fn) \
        case __NR_ ## fn: retval = emu_ ## fn (context, \
                state->__rdi, state->__rsi, state->__rdx, \
                state->__rcx, state->__r8, state->__r9); break;

static void emu_syscall(syscall_context_t *context, x86_thread_state64_t *state) {
        uint64_t retval;

        switch(state->__rax) {
                SYSCALL3(write);
                SYSCALL1(exit);

        default:
                DEBUG("unknown syscall %lld, aborting", state->__rax);
                PRINT_STATE(*state);
                task_terminate(context->task);
                return;
        }

        if(retval != SYSCALL_SUSPEND)
                emu_syscall_return(context, retval, state);
}

#undef SYSCALL1
#undef SYSCALL2
#undef SYSCALL3
#undef SYSCALL4
#undef SYSCALL5
#undef SYSCALL6

static kern_return_t emu_exn_wait(mach_port_t exn_set) {
        kern_return_t retval;

        struct {
                mach_msg_header_t hdr;
                mach_msg_body_t body;
                mach_msg_port_descriptor_t thread_port;
                mach_msg_port_descriptor_t task_port;
                NDR_record_t NDR;
                exception_type_t exception;
                mach_msg_type_number_t code_len;
                int64_t code[2];
                int flavor;
                mach_msg_type_number_t state_len;
                natural_t state[sizeof(x86_thread_state64_t) / sizeof(natural_t)];
                mach_msg_trailer_t trail;
        } __attribute__((packed)) exn_req = {{0}};
        exn_req.hdr.msgh_size = sizeof(exn_req);
        exn_req.hdr.msgh_local_port = exn_set;
        if((retval = mach_msg_receive(&exn_req.hdr)))
                FAIL("mach_msg_receive", retval);

        x86_thread_state64_t *state = (x86_thread_state64_t*) exn_req.state;

        if(exn_req.exception == EXC_SYSCALL) {
                syscall_context_t context = {
                        .sysret_port = exn_req.hdr.msgh_remote_port,
                        .task = exn_req.task_port.name,
                        .thread = exn_req.thread_port.name,
                };
                emu_syscall(&context, state);
        } else {
                const char* exn_str = "(unknown)";
                switch(exn_req.exception) {
                case EXC_BAD_ACCESS: exn_str = "EXC_BAD_ACCESS"; break;
                case EXC_BAD_INSTRUCTION: exn_str = "EXC_BAD_INSTRUCTION"; break;
                case EXC_ARITHMETIC: exn_str = "EXC_ARITHMETIC"; break;
                case EXC_EMULATION: exn_str = "EXC_EMULATION"; break;
                case EXC_SOFTWARE: exn_str = "EXC_SOFTWARE"; break;
                case EXC_BREAKPOINT: exn_str = "EXC_BREAKPOINT"; break;
                case EXC_SYSCALL: exn_str = "EXC_SYSCALL"; break;
                case EXC_MACH_SYSCALL: exn_str = "EXC_MACH_SYSCALL"; break;
                case EXC_RPC_ALERT: exn_str = "EXC_RPC_ALERT"; break;
                case EXC_CRASH: exn_str = "EXC_CRASH"; break;
                case EXC_RESOURCE: exn_str = "EXC_RESOURCE"; break;
                default:
                        if(exn_req.exception >= 0x10000 && exn_req.exception <= 0x1ffff)
                                exn_str = "Unix signal";
                        else if(exn_req.exception >= 0x20000 && exn_req.exception <= 0x2ffff)
                                exn_str = "MACF exception";
                }
                DEBUG("exception %d (%s) %016llx %016llx",
                      exn_req.exception, exn_str, exn_req.code[0], exn_req.code[1]);
                PRINT_STATE(*state);
                task_terminate(exn_req.task_port.name);
        }

fail:
        return retval;
}

static void emu_syscall_return(syscall_context_t *context, uint64_t syscall_retval,
                               x86_thread_state64_t *state) {
        kern_return_t retval;

        state->__rax = syscall_retval;

        if((retval = thread_set_state(context->thread, x86_THREAD_STATE64, (natural_t*) state,
                        sizeof(x86_thread_state64_t) / sizeof(natural_t))))
                FAIL("thread_set_state", retval);

        struct {
                mach_msg_header_t hdr;
                NDR_record_t NDR;
                kern_return_t ret_code;
                int flavor;
                mach_msg_type_number_t state_len;
        } __attribute__((packed)) exn_rep = {{0}};
        exn_rep.hdr.msgh_size = sizeof(exn_rep);
        exn_rep.hdr.msgh_remote_port = context->sysret_port;
        exn_rep.hdr.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_MOVE_SEND_ONCE);
        // TODO: kernel seems to ignore NDR, should we set it?
        //exn_rep.NDR = exn_req.NDR;
        exn_rep.ret_code = KERN_SUCCESS;
        // TODO: kernel seems to ignore returned state, wtf?
        if((retval = mach_msg_send(&exn_rep.hdr)))
                FAIL("mach_msg_send", retval);

fail:   ; /* nothing */
}

static void emu_syscall_return_nostate(syscall_context_t *context, uint64_t syscall_retval) {
        kern_return_t retval;
        x86_thread_state64_t state;
        mach_msg_type_number_t state_len;

        if((retval = thread_get_state(context->thread, x86_THREAD_STATE64,
                        (natural_t*) &state, &state_len)))
                FAIL("thread_set_state", retval);

        emu_syscall_return(context, syscall_retval, &state);

fail:   ; /* nothing */
}

void happy_dance() {
        kern_return_t retval, xretval;
        mach_port_t exn_set = 0;

        if((retval = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &exn_set)))
                FAIL("mach_port_allocate", retval);

        //DEBUG("exn set port %d", exn_set);

        if((retval = emu_spawn_task(exn_set)))
                FAIL("emu_spawn_task", retval);

        while(TRUE) {
                if((retval = emu_exn_wait(exn_set)))
                        FAIL("emu_exn_wait", retval);
        }

fail:
        if(exn_set && (xretval = mach_port_deallocate(mach_task_self(), exn_set)))
                XFAIL("mach_port_deallocate:exn_set", xretval);
}

int main(int argc, char** argv) {
        happy_dance();
}
