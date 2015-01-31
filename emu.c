#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <llvm-c/Target.h>
#include <llvm-c/Disassembler.h>

#include <bits/syscall.h>
#include <asm-generic/errno.h>
#include <elf.h>

// from mach/i386/pmap.h
typedef uint64_t  pmap_paddr_t;

#define DEBUG1(str) fprintf(stderr, "d: %s: " str "\n", __func__)
#define DEBUG(fmt, ...) fprintf(stderr, "d: %s: " fmt "\n", __func__, __VA_ARGS__)
#define FAIL(reason, retval) do { fail(__func__, reason, retval); goto fail; } while(0)
#define XFAIL(reason, retval) fail(__func__, "cleanup:" reason, retval)
#define PFAIL(reason) do { fprintf(stderr, "e: %s: %s\n", __func__, reason); goto fail; } while(0)
#define UFAIL(reason, retval) do { fprintf(stderr, "e: %s: %s: %s\n", __func__, reason, strerror(retval)); goto fail; } while(0)
#define XUFAIL(reason, retval) fprintf(stderr, "e: %s: cleanup: %s: %s\n", __func__, reason, strerror(retval))
#define ASSERT(expr) do { if(!(expr)) { fprintf(stderr, "e: %s: failed: %s\n", __func__, #expr); goto fail; } } while(0)

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

        char *argv[] = {0}, *envp[] = {0};
        execve("./empty", argv, envp);

fail:
        exit(1);
}

/* spawn a new suspended task */
static kern_return_t emu_spawn(mach_port_t exn, mach_port_t *task) {
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

        if((retval = task_set_exception_ports(child,
                        EXC_MASK_ALL, exn,
                        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, x86_THREAD_STATE64)))
                FAIL("task_set_exception_ports", retval);

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

static kern_return_t emu_exn_wait(mach_port_t exn_set);

static kern_return_t emu_blank_slate(mach_port_t exn_set, task_t *task, thread_t *thread) {
        kern_return_t retval, xretval;
        mach_port_t exn = 0, exn_send = 0;
        mach_msg_type_name_t type;
        thread_array_t threads = NULL;
        mach_msg_type_number_t thread_count;

        if((retval = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exn)))
                FAIL("mach_port_allocate", retval);

        if((retval = mach_port_extract_right(mach_task_self(),
                        exn, MACH_MSG_TYPE_MAKE_SEND, &exn_send, &type)))
                FAIL("mach_port_extract_right", retval);

        //DEBUG("exn port %d", exn);

        if((retval = emu_spawn(exn, task)))
                FAIL("emu_spawn", retval);

        if((retval = task_threads(*task, &threads, &thread_count)))
                FAIL("task_threads", retval);

        if((retval = emu_exn_wait(exn)))
                FAIL("emu_exn_wait", retval);

        if((retval = mach_port_move_member(mach_task_self(), exn, exn_set)))
                FAIL("mach_port_move_member", retval);

        *thread = threads[0];

fail:
        if(retval) {
                if(task && (xretval = mach_port_deallocate(mach_task_self(), *task)))
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
                FAIL("vm_deallocate", retval);

fail:   abort();
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

static boolean_t emu_syscall(syscall_context_t *context, x86_thread_state64_t *state) {
        uint64_t retval = 0;

        switch(state->__rax) {
                SYSCALL3(write);
                SYSCALL1(exit);

        /* pseudo-syscall indicating macho stub handoff */
        case 0xffff:
                if((retval = thread_suspend(context->thread)))
                        return FALSE;
                break;

        default:
                DEBUG("unknown syscall %lld, aborting", state->__rax);
                return FALSE;
        }

        if(retval != SYSCALL_SUSPEND)
                emu_syscall_return(context, retval, state);

        return TRUE;
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
        syscall_context_t context = {
                .sysret_port = exn_req.hdr.msgh_remote_port,
                .task = exn_req.task_port.name,
                .thread = exn_req.thread_port.name,
        };

        if(exn_req.exception == EXC_SYSCALL && emu_syscall(&context, state)) {
                /* handled */
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

                uint64_t stack[10] = {0xBAAAAAAAAAAAAAAD};
                uint64_t rsp_low = state->__rsp;
                vm_size_t rsp_len = sizeof(stack) / sizeof(natural_t);
                if((retval = vm_read_overwrite(context.task, rsp_low, sizeof(stack),
                                (pointer_t) stack, &rsp_len))) {
                        DEBUG1("invalid stack");
                } else {
                        DEBUG1("stack:");
                        for(int i = 0; i < sizeof(stack) / sizeof(stack[0]); i++) {
                                const char *arrow =
                                        (rsp_low + i * sizeof(stack[0]) == state->__rsp) ? "=>" : "  ";
                                DEBUG(" %s %016llx: %016llx", arrow,
                                      rsp_low + i * sizeof(stack[0]), stack[i]);
                        }
                }

                uint8_t insns_begin[256];
                uint8_t *insns = insns_begin, *insns_end;
                vm_size_t rip_len = sizeof(insns_begin) / sizeof(natural_t);
                if((retval = vm_read_overwrite(context.task, state->__rip, sizeof(insns_begin),
                                (pointer_t) insns_begin, &rip_len)))
                        FAIL("vm_read_overwrite:insns", retval);
                insns_end = insns_begin + rip_len * sizeof(natural_t);

                LLVMInitializeAllTargetInfos();
                LLVMInitializeAllTargetMCs();
                LLVMInitializeAllDisassemblers();
                LLVMDisasmContextRef Disasm = LLVMCreateDisasm(
                        "x86_64-apple-darwin12.6.0", NULL, 0, NULL, NULL);
                if(!Disasm)
                        PFAIL("LLVMCreateDisasm");

                DEBUG1("disasm:");
                for(int i = 0; i < 10; i++) {
                        char mnemonic[256] = {0};
                        uint64_t rip = state->__rip + (insns - insns_begin);
                        size_t insn_len = LLVMDisasmInstruction(Disasm, insns, insns_end - insns,
                                rip, mnemonic, sizeof(mnemonic));

                        char bytes[3 * 8 + 1] = {0};
                        int j;
                        for(j = 0; j < insn_len; j++) {
                                snprintf(bytes + (j % 8) * 3, 4, "%02x ", insns[j]);
                                if(j > 0 && j % 8 == 7) {
                                        DEBUG(" %s %016llx: %s", (i == 0 && j == 7 ? "=>" : "  "),
                                              rip + j - 7, bytes);
                                        memset(bytes, 0x20, sizeof(bytes));
                                }
                        }
                        memset(bytes + strlen(bytes), 0x20, sizeof(bytes) - strlen(bytes) - 1);

                        DEBUG(" %s %016llx: %s %s",
                              (i == 0 && j < 8 ? "=>" : "  "), rip + j - (j % 8),
                              bytes, mnemonic + 1);

                        insns += insn_len;
                }

                LLVMDisasmDispose(Disasm);

                task_terminate(context.task);

                retval = KERN_FAILURE;
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

static kern_return_t emu_readelf(task_t task, thread_t thread, void *image) {
        kern_return_t retval = 0;

        Elf64_Ehdr *ehdr = image;
        ASSERT(!memcmp(ehdr->e_ident, ELFMAG, SELFMAG));
        ASSERT(ehdr->e_ident[EI_CLASS] == ELFCLASS64);
        ASSERT(ehdr->e_ident[EI_DATA] == ELFDATA2LSB);
        ASSERT(ehdr->e_ident[EI_VERSION] == EV_CURRENT);
        ASSERT(ehdr->e_ident[EI_OSABI] == ELFOSABI_SYSV);
        ASSERT(ehdr->e_type == ET_EXEC);
        ASSERT(ehdr->e_machine == EM_X86_64);

        int executable_stack = 0;

        for(int i = 0; i < ehdr->e_phnum; i++) {
                Elf64_Phdr *phdr = (Elf64_Phdr*) ((uint8_t*)image +
                        ehdr->e_phoff + i * ehdr->e_phentsize);

                switch(phdr->p_type) {
                case PT_LOAD: {
                        vm_prot_t vm_prot = 0;
                        if(phdr->p_flags & PF_R)
                                vm_prot |= VM_PROT_READ;
                        if(phdr->p_flags & PF_W)
                                vm_prot |= VM_PROT_WRITE;
                        if(phdr->p_flags & PF_X)
                                vm_prot |= VM_PROT_EXECUTE;

                        if(phdr->p_filesz > 0) {
                                vm_address_t source_addr = (vm_address_t) image + phdr->p_offset;
                                vm_address_t target_addr = (vm_address_t) phdr->p_vaddr;

                                DEBUG("src %016lx dst %016lx sz %016llx",
                                      source_addr, target_addr, phdr->p_filesz);

                                vm_prot_t cur, max;
                                if((retval = vm_remap(task, &target_addr, phdr->p_filesz,
                                                0, FALSE, mach_task_self(), source_addr,
                                                TRUE, &cur, &max, VM_INHERIT_NONE)))
                                        FAIL("vm_allocate", retval);

                                DEBUG("dst %016lx", target_addr);
                                ASSERT(target_addr == (vm_address_t) phdr->p_vaddr);
                        }

                        break;
                }

                case PT_GNU_STACK:
                        executable_stack = !!(phdr->p_flags & PF_X);
                        break;

                default:
                        PFAIL("unknown phdr->p_type");
                }
        }

        x86_thread_state64_t state = {0};
        state.__rip = ehdr->e_entry;
        if((retval = thread_set_state(thread, x86_THREAD_STATE64, (natural_t*) &state,
                        sizeof(x86_thread_state64_t) / sizeof(natural_t))))
                FAIL("thread_set_state", retval);

        if((retval = thread_resume(thread)))
                FAIL("thread_resume", retval);

fail:
        return retval;
}

static void happy_dance(const char *init) {
        kern_return_t retval, xretval;
        mach_port_t exn_set = 0;
        int ret, xret;
        int fd = 0;
        void *image = NULL;

        if(!(fd = open(init, O_RDONLY)))
                UFAIL("open", fd);

        struct stat st;
        if((ret = fstat(fd, &st)))
                UFAIL("fstat", ret);

        if((image = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
                UFAIL("mmap", errno);

        close(fd);
        fd = 0;

        if((retval = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &exn_set)))
                FAIL("mach_port_allocate", retval);

        //DEBUG("exn set port %d", exn_set);

        task_t task;
        thread_t thread;
        if((retval = emu_blank_slate(exn_set, &task, &thread)))
                FAIL("emu_blank_slate", retval);

        if((retval = emu_readelf(task, thread, image)))
                FAIL("emu_readelf", retval);

        while(TRUE) {
                if((retval = emu_exn_wait(exn_set)))
                        FAIL("emu_exn_wait", retval);
        }

fail:
        if(exn_set && (xretval = mach_port_deallocate(mach_task_self(), exn_set)))
                XFAIL("mach_port_deallocate:exn_set", xretval);

        if(image && (xret = munmap(image, st.st_size)))
                XUFAIL("munmap", xret);

        if(fd)
                close(fd);
}

int main(int argc, char** argv) {
        if(argc != 2) {
                fprintf(stderr, "usage: %s [init]\n", argv[0]);
                return 1;
        }

        happy_dance(argv[1]);
}
