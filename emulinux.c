#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <mach/mach.h>
#include <mach/mig.h>

#include "mach_exc.h"

#ifndef NDEBUG
#define DEBUG(fmt, ...) fprintf(stderr, "d: %s: " fmt "\n", __func__, __VA_ARGS__)
#define FAIL(reason, retval) do { fail(__func__, reason, retval); goto fail; } while(0)
#define XFAIL(reason, retval) fail(__func__, "cleanup:" reason, retval)
#else
#define DEBUG(...) do ; while(0)
#define FAIL(reason, retval) goto fail
#define XFAIL(reason, retval) do ; while(0)
#endif

void fail(const char *fn, const char *reason, kern_return_t retval) {
        fprintf(stderr, "e: %s: %s: %08x %s\n", fn, reason, retval, mach_error_string(retval));
}

/* do the port swap dance in newly forked task */
void emu_spawn_helper() {
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
        } task_msg = {0};
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
        } bootstrap_msg = {0};
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
        if(execve("./linux", argv, envp))
                perror("execve");

fail:
        exit(1);
}

/* spawn a new suspended task */
kern_return_t emu_spawn(mach_port_t *task) {
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

        if(!fork())
                emu_spawn_helper();

        if((retval = task_set_bootstrap_port(mach_task_self(), old_bootstrap)))
                FAIL("task_set_bootstrap_port", retval);

        struct {
                mach_msg_header_t hdr;
                mach_msg_body_t body;
                mach_msg_port_descriptor_t task_port;
                mach_msg_trailer_t trail;
        } task_msg = {0};
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

void print_x86_64_thread_state(x86_thread_state64_t *state) {
        DEBUG("RAX %016llx R8  %016llx", state->__rax, state->__r8);
        DEBUG("RBX %016llx R9  %016llx", state->__rbx, state->__r9);
        DEBUG("RCX %016llx R10 %016llx", state->__rcx, state->__r10);
        DEBUG("RDX %016llx R11 %016llx", state->__rdx, state->__r11);
        DEBUG("RDI %016llx R12 %016llx", state->__rdi, state->__r12);
        DEBUG("RSI %016llx R13 %016llx", state->__rsi, state->__r13);
        DEBUG("RBP %016llx R14 %016llx", state->__rbp, state->__r14);
        DEBUG("RSP %016llx R15 %016llx", state->__rsp, state->__r15);
        DEBUG("CS:RIP %04x:%016llx FS %04x GS %04x",
              (uint16_t) state->__cs, state->__rip,
              (uint16_t) state->__fs, (uint16_t) state->__gs);
        DEBUG("RFLAGS %016llx", state->__rflags);
}

kern_return_t happy_dance() {
        kern_return_t retval, xretval;
        mach_port_t task = 0, exn = 0, exn_send = 0;
        mach_msg_type_name_t type;
        thread_array_t threads = NULL;
        mach_msg_type_number_t thread_count;

        if((retval = emu_spawn(&task)))
                FAIL("emu_spawn", retval);

        if((retval = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exn)))
                FAIL("mach_port_allocate", retval);

        if((retval = mach_port_extract_right(mach_task_self(),
                        exn, MACH_MSG_TYPE_MAKE_SEND, &exn_send, &type)))
                FAIL("mach_port_extract_right", retval);

        if((retval = task_set_exception_ports(task,
                        EXC_MASK_SYSCALL, exn_send,
                        EXCEPTION_STATE_IDENTITY, x86_THREAD_STATE64)))
                FAIL("task_set_exception_ports", retval);

        if((retval = task_threads(task, &threads, &thread_count)))
                FAIL("task_threads", retval);

        DEBUG("%d threads", thread_count);

        usleep(1000);
        if((retval = thread_resume(threads[0])))
                FAIL("thread_resume", retval);

        while(TRUE) {
                struct {
                        mach_msg_header_t hdr;
                        mach_msg_body_t body;
                        mach_msg_port_descriptor_t thread_port;
                        mach_msg_port_descriptor_t task_port;
                        NDR_record_t NDR;
                        exception_type_t exception;
                        mach_msg_type_number_t code_len;
                        int32_t code[2];
                        int flavor;
                        mach_msg_type_number_t state_len;
                        natural_t state[sizeof(x86_thread_state64_t) / sizeof(natural_t)];
                        mach_msg_trailer_t trail;
                } __attribute__((packed)) exn_req = {0};
                exn_req.hdr.msgh_size = sizeof(exn_req);
                exn_req.hdr.msgh_local_port = exn;
                if((retval = mach_msg_receive(&exn_req.hdr)))
                        FAIL("mach_msg_receive:exn", retval);

                // DEBUG("remote %d %08x thread %d task %d",
                //       exn_req.hdr.msgh_remote_port, exn_req.hdr.msgh_bits,
                //       exn_req.thread_port.name, exn_req.task_port.name);
                DEBUG("exn %d code[%d] %08x %08x flavor %d state[%d]",
                     exn_req.exception,
                     exn_req.code_len, exn_req.code[0], exn_req.code[1],
                     exn_req.flavor, exn_req.state_len);

                x86_thread_state64_t *state = (x86_thread_state64_t*) exn_req.state;
                print_x86_64_thread_state(state);

                struct {
                        mach_msg_header_t hdr;
                        NDR_record_t NDR;
                        kern_return_t ret_code;
                        int flavor;
                        mach_msg_type_number_t state_len;
                        natural_t state[sizeof(x86_thread_state64_t) / sizeof(natural_t)];
                } __attribute__((packed)) exn_rep = {0};
                exn_rep.hdr.msgh_size = sizeof(exn_rep);
                exn_rep.hdr.msgh_remote_port = exn_req.hdr.msgh_remote_port;
                exn_rep.hdr.msgh_bits = exn_req.hdr.msgh_bits & MACH_MSGH_BITS_REMOTE_MASK;
                exn_rep.NDR = exn_req.NDR;
                exn_rep.ret_code = KERN_SUCCESS;
                exn_rep.flavor = x86_THREAD_STATE64;
                exn_rep.state_len = sizeof(x86_thread_state64_t) / sizeof(natural_t);
                memcpy(exn_rep.state, state, sizeof(x86_thread_state64_t));
                if((retval = mach_msg_send(&exn_rep.hdr)))
                        FAIL("mach_msg_send:exn", retval);
        }

fail:
        if(task && (xretval = mach_port_deallocate(mach_task_self(), task)))
                XFAIL("mach_port_deallocate:task", xretval);

        if(threads && (xretval = vm_deallocate(mach_task_self(),
                        (vm_address_t) threads, sizeof(thread_t) * thread_count)))
                XFAIL("vm_deallocate:threads", xretval);

        return retval;
}

int main(int argc, char** argv) {
        happy_dance();
}
