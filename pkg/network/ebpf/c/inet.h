#ifndef __INET_H
#define __INET_H

//region sys_enter_bind

static __always_inline int sys_enter_bind(struct socket* sock, struct sockaddr* addr) {
    __u64 tid = bpf_get_current_pid_tgid();

    __u16 type = 0;
    bpf_probe_read(&type, sizeof(__u16), &sock->type);
    if ((type & SOCK_DGRAM) == 0) {
        return 0;
    }

    if (addr == NULL) {
        log_debug("sys_enter_bind: could not read sockaddr, sock=%llx, tid=%u\n", sock, tid);
        return 0;
    }

    u16 sin_port = 0;
    sa_family_t family = 0;
    bpf_probe_read(&family, sizeof(sa_family_t), &addr->sa_family);
    if (family == AF_INET) {
        bpf_probe_read(&sin_port, sizeof(u16), &(((struct sockaddr_in*)addr)->sin_port));
    } else if (family == AF_INET6) {
        bpf_probe_read(&sin_port, sizeof(u16), &(((struct sockaddr_in6*)addr)->sin6_port));
    }

    sin_port = ntohs(sin_port);
    if (sin_port == 0) {
        log_debug("ERR(sys_enter_bind): sin_port is 0\n");
        return 0;
    }

    // write to pending_binds so the retprobe knows we can mark this as binding.
    bind_syscall_args_t args = {};
    args.port = sin_port;

    bpf_map_update_elem(&pending_bind, &tid, &args, BPF_ANY);
    log_debug("sys_enter_bind: started a bind on UDP port=%d sock=%llx tid=%u\n", sin_port, sock, tid);

    return 0;
}

SEC("kprobe/inet_bind")
int kprobe__inet_bind(struct pt_regs* ctx) {
    struct socket *sock = (struct socket*)PT_REGS_PARM1(ctx);
    struct sockaddr* addr = (struct sockaddr*)PT_REGS_PARM2(ctx);
    log_debug("kprobe/inet_bind: sock=%llx, umyaddr=%x\n", sock, addr);
    return sys_enter_bind(sock, addr);
}

SEC("kprobe/inet6_bind")
int kprobe__inet6_bind(struct pt_regs* ctx) {
    struct socket *sock = (struct socket*)PT_REGS_PARM1(ctx);
    struct sockaddr* addr = (struct sockaddr*)PT_REGS_PARM2(ctx);
    log_debug("kprobe/inet6_bind: sock=%llx, umyaddr=%x\n", sock, addr);
    return sys_enter_bind(sock, addr);
}

//endregion

//region sys_exit_bind

static __always_inline int sys_exit_bind(__s64 ret) {
    __u64 tid = bpf_get_current_pid_tgid();

    // bail if this bind() is not the one we're instrumenting
    bind_syscall_args_t* args;
    args = bpf_map_lookup_elem(&pending_bind, &tid);

    log_debug("sys_exit_bind: tid=%u, ret=%d\n", tid, ret);

    if (args == NULL) {
        log_debug("sys_exit_bind: was not a UDP bind, will not process\n");
        return 0;
    }

    bpf_map_delete_elem(&pending_bind, &tid);

    if (ret != 0) {
        return 0;
    }

    __u16 sin_port = args->port;
    __u8 port_state = PORT_LISTENING;
    port_binding_t t = {};
    t.netns = 0; // don't have net ns info in this context
    t.port = sin_port;
    bpf_map_update_elem(&udp_port_bindings, &t, &port_state, BPF_ANY);
    log_debug("sys_exit_bind: bound UDP port %u\n", sin_port);

    return 0;
}

SEC("kretprobe/inet_bind")
int kretprobe__inet_bind(struct pt_regs* ctx) {
    __s64 ret = PT_REGS_RC(ctx);
    log_debug("kretprobe/inet_bind: ret=%d\n", ret);
    return sys_exit_bind(ret);
}

SEC("kretprobe/inet6_bind")
int kretprobe__inet6_bind(struct pt_regs* ctx) {
    __s64 ret = PT_REGS_RC(ctx);
    log_debug("kretprobe/inet6_bind: ret=%d\n", ret);
    return sys_exit_bind(ret);
}

#endif
