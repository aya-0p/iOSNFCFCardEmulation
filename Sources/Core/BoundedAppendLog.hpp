#ifndef NFCF_BOUNDED_APPEND_LOG_HPP
#define NFCF_BOUNDED_APPEND_LOG_HPP

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const off_t kNFCFLogLimit = 1024 * 1024;

typedef struct {
    const char *path;
    int fd;
    off_t size;
    pthread_mutex_t mutex;
} NFCFBoundedAppendLog;

#define NFCF_BOUNDED_APPEND_LOG_INITIALIZER(log_path) \
    { log_path, -1, 0, PTHREAD_MUTEX_INITIALIZER }

static inline void NFCFLogPreviousPath(const char *path, char previous[1024]) {
    (void)snprintf(previous, 1024, "%s.previous", path);
    previous[1023] = '\0';
}

static inline void NFCFResetBoundedAppendLog(NFCFBoundedAppendLog *log) {
    char previous[1024];
    NFCFLogPreviousPath(log->path, previous);
    (void)unlink(log->path);
    (void)unlink(previous);
}

static inline int NFCFOpenBoundedAppendLog(NFCFBoundedAppendLog *log) {
    log->fd = open(log->path,
                   O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                   0600);
    if (log->fd < 0) return -1;
    struct stat info = {};
    if (fstat(log->fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != getuid() || (info.st_mode & 077) != 0 ||
        fchmod(log->fd, 0600) != 0) {
        close(log->fd);
        log->fd = -1;
        return -1;
    }
    log->size = info.st_size > 0 ? info.st_size : 0;
    return 0;
}

static inline void NFCFRotateBoundedAppendLog(NFCFBoundedAppendLog *log) {
    if (log->fd >= 0) close(log->fd);
    log->fd = -1;
    log->size = 0;
    char previous[1024];
    NFCFLogPreviousPath(log->path, previous);
    (void)unlink(previous);
    if (rename(log->path, previous) != 0) {
        int fd = open(log->path,
                      O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                      0600);
        if (fd >= 0) close(fd);
    }
}

static inline void NFCFWriteBoundedAppendLog(NFCFBoundedAppendLog *log,
                                             const char *bytes,
                                             size_t length) {
    if (log == NULL || bytes == NULL || length == 0) return;
    pthread_mutex_lock(&log->mutex);
    if (log->fd < 0 && NFCFOpenBoundedAppendLog(log) != 0) {
        pthread_mutex_unlock(&log->mutex);
        return;
    }
    if (log->size > 0 && log->size + (off_t)length > kNFCFLogLimit) {
        NFCFRotateBoundedAppendLog(log);
        if (NFCFOpenBoundedAppendLog(log) != 0) {
            pthread_mutex_unlock(&log->mutex);
            return;
        }
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(log->fd, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            close(log->fd);
            log->fd = -1;
            break;
        }
        offset += (size_t)written;
        log->size += written;
    }
    pthread_mutex_unlock(&log->mutex);
}

static inline void NFCFCloseBoundedAppendLog(NFCFBoundedAppendLog *log) {
    if (log == NULL) return;
    pthread_mutex_lock(&log->mutex);
    if (log->fd >= 0) close(log->fd);
    log->fd = -1;
    log->size = 0;
    pthread_mutex_unlock(&log->mutex);
}

#endif
