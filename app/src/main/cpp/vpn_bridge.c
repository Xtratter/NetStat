#include <errno.h>
#include <jni.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#include "zdtun/zdtun.h"

struct tunnel {
    JNIEnv *env;
    jobject callbacks;
    jmethodID protect_socket;
    jmethodID should_run;
    jmethodID on_packet;
    int fd;
    int dropped;
    int error;
    int stopped;
};

static int report_packet(struct tunnel *t, const char *packet, int length, jboolean outgoing) {
    JNIEnv *env = t->env;
    jbyteArray bytes = (*env)->NewByteArray(env, length);
    if (bytes == NULL) {
        t->stopped = 1;
        return 0;
    }
    (*env)->SetByteArrayRegion(env, bytes, 0, length, (const jbyte *)packet);
    int keep_running = (*env)->CallBooleanMethod(env, t->callbacks, t->on_packet, bytes, outgoing, t->dropped);
    (*env)->DeleteLocalRef(env, bytes);
    if ((*env)->ExceptionCheck(env) || !keep_running) t->stopped = 1;
    return !t->stopped;
}

static int send_to_tun(zdtun_t *engine, zdtun_pkt_t *packet, const zdtun_conn_t *connection) {
    (void)connection;
    struct tunnel *t = zdtun_userdata(engine);
    if (t->stopped) return -1;
    ssize_t written;
    do {
        written = write(t->fd, packet->buf, packet->len);
    } while (written < 0 && errno == EINTR);
    if (written == packet->len) {
        report_packet(t, packet->buf, packet->len, JNI_FALSE);
    } else if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        t->dropped++;
    } else {
        t->error = written < 0 ? errno : EIO;
        t->stopped = 1;
        return -1;
    }
    return 0;
}

static int protect_socket(zdtun_t *engine, socket_t fd) {
    struct tunnel *t = zdtun_userdata(engine);
    if (t->stopped) return -1;
    JNIEnv *env = t->env;
    jboolean allowed = (*env)->CallBooleanMethod(env, t->callbacks, t->protect_socket, (jint)fd);
    if (!allowed || (*env)->ExceptionCheck(env)) {
        t->error = ENETUNREACH;
        t->stopped = 1;
        return -1;
    }
    return 0;
}

JNIEXPORT jint JNICALL
Java_io_github_xtratter_netstat_capture_VpnNative_run(
        JNIEnv *env, jobject self, jint fd, jint mtu, jobject callbacks) {
    (void)self;
    if (fd < 0 || fd >= FD_SETSIZE || mtu < 1280 || mtu > 4096) return EINVAL;
    jclass type = (*env)->GetObjectClass(env, callbacks);
    if (type == NULL) return EINVAL;
    struct tunnel t = {.env = env, .callbacks = callbacks, .fd = fd};
    t.protect_socket = (*env)->GetMethodID(env, type, "protectSocket", "(I)Z");
    if (t.protect_socket == NULL) return EINVAL;
    t.should_run = (*env)->GetMethodID(env, type, "shouldRun", "()Z");
    if (t.should_run == NULL) return EINVAL;
    t.on_packet = (*env)->GetMethodID(env, type, "onPacket", "([BZI)Z");
    if (t.on_packet == NULL) return EINVAL;

    zdtun_callbacks_t hooks = {.send_client = send_to_tun, .on_socket_open = protect_socket};
    zdtun_t *engine = zdtun_init(&hooks, &t);
    if (engine == NULL) return ENOMEM;
    zdtun_set_mtu(engine, mtu);
    char packet[4096];
    struct timespec now = {0};
    time_t last_purge = 0;
    while (!t.stopped && (*env)->CallBooleanMethod(env, callbacks, t.should_run) &&
           !(*env)->ExceptionCheck(env)) {
        fd_set reads, writes;
        int last = fd;
        zdtun_fds(engine, &last, &reads, &writes);
        if (last < fd) last = fd;
        FD_SET(fd, &reads);
        struct timeval timeout = {.tv_usec = 150000};
        int ready = select(last + 1, &reads, &writes, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            t.error = errno;
            break;
        }
        if (ready > 0) {
            // Work on the old socket set before forwarding a TUN packet that may open or close sockets.
            zdtun_handle_fd(engine, &reads, &writes);
            if (!t.stopped && FD_ISSET(fd, &reads)) {
                ssize_t length = read(fd, packet, sizeof(packet));
                if (length > 0) {
                    if (report_packet(&t, packet, (int)length, JNI_TRUE)) {
                        zdtun_easy_forward(engine, packet, (int)length);
                    }
                } else if (length == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    t.error = length == 0 ? EIO : errno;
                    break;
                }
            }
        }
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec != last_purge) {
            last_purge = now.tv_sec;
            zdtun_purge_expired(engine);
        }
    }
    t.stopped = 1;
    zdtun_finalize(engine);
    return t.error;
}
