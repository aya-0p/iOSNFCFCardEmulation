#include "SecureFile.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace nfcf_backend {

static bool WriteAll(int fd, const void *bytes, size_t length) {
    const uint8_t *cursor = static_cast<const uint8_t *>(bytes);
    while (length != 0) {
        ssize_t count = write(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        cursor += count;
        length -= static_cast<size_t>(count);
    }
    return true;
}

static int OpenReadableFile(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0 || errno != ENOENT) return fd;

    if (strncmp(path, "/var/mobile/", 12) == 0) {
        const char *roots[] = {
            "/rootfs/private/var/mobile/Containers/Shared/AppGroup",
            "/private/var/mobile/Containers/Shared/AppGroup",
            "/var/mobile/Containers/Shared/AppGroup",
        };
        for (const char *root : roots) {
            DIR *directory = opendir(root);
            if (directory == nullptr) {
                fprintf(stderr, "ReadSecureFileExact opendir failed: %s "
                                "errno=%d (%s)\n",
                        root, errno, strerror(errno));
                continue;
            }
            struct dirent *entry = nullptr;
            while ((entry = readdir(directory)) != nullptr) {
                if (strncmp(entry->d_name, ".jbroot-", 8) != 0) continue;
                char rootless_path[PATH_MAX] = {};
                int count = snprintf(rootless_path, sizeof(rootless_path),
                                     "%s/%s%s", root, entry->d_name, path);
                if (count > 0 &&
                    static_cast<size_t>(count) < sizeof(rootless_path)) {
                    fd = open(rootless_path, O_RDONLY);
                    if (fd >= 0) {
                        closedir(directory);
                        return fd;
                    }
                    fprintf(stderr, "ReadSecureFileExact candidate failed: %s "
                                    "errno=%d (%s)\n",
                            rootless_path, errno, strerror(errno));
                }
            }
            closedir(directory);
        }
    }

    char resolved[PATH_MAX] = {};
    if (realpath(path, resolved) != nullptr) {
        fd = open(resolved, O_RDONLY);
        if (fd >= 0 || errno != ENOENT) return fd;
        if (strncmp(resolved, "/rootfs/", 8) != 0) {
            char rootfs_path[PATH_MAX] = {};
            int count = snprintf(rootfs_path, sizeof(rootfs_path),
                                 "/rootfs%s", resolved);
            if (count > 0 && static_cast<size_t>(count) < sizeof(rootfs_path))
                return open(rootfs_path, O_RDONLY);
        }
    }
    return -1;
}

bool EnsurePrivateDirectory(const char *path) {
    if (path == nullptr || path[0] != '/') return false;
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return false;
    struct stat info = {};
    if (lstat(path, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != getuid() || (info.st_mode & 077) != 0) {
        return false;
    }
    return chmod(path, 0700) == 0;
}

bool WriteSecureFileAtomically(const char *path, const void *bytes,
                               size_t length) {
    if (path == nullptr || path[0] != '/' || bytes == nullptr || length == 0)
        return false;
    char temporary[PATH_MAX] = {};
    int count = snprintf(temporary, sizeof(temporary), "%s.tmp.%d", path,
                         getpid());
    if (count <= 0 || static_cast<size_t>(count) >= sizeof(temporary))
        return false;
    (void)unlink(temporary);
    int fd = open(temporary,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    if (fd < 0) return false;
    bool success = fchmod(fd, 0600) == 0 && WriteAll(fd, bytes, length) &&
                   fsync(fd) == 0;
    if (close(fd) != 0) success = false;
    if (success && rename(temporary, path) != 0) success = false;
    if (!success) (void)unlink(temporary);
    return success;
}

bool WriteSecureTextFile(const char *path, const char *text) {
    return text != nullptr &&
           WriteSecureFileAtomically(path, text, strlen(text));
}

bool ReadSecureFileExact(const char *path, void *bytes, size_t length,
                         uid_t expected_owner) {
    if (path == nullptr || bytes == nullptr || length == 0) return false;
    int fd = OpenReadableFile(path);
    if (fd < 0) {
        fprintf(stderr, "ReadSecureFileExact open failed: %s errno=%d (%s)\n",
                path, errno, strerror(errno));
        return false;
    }
    struct stat info = {};
    bool metadata_valid =
        fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_uid == expected_owner && (info.st_mode & 0777) == 0600 &&
        info.st_size == static_cast<off_t>(length);
    if (!metadata_valid) {
        fprintf(stderr,
                "ReadSecureFileExact metadata invalid: path=%s uid=%u "
                "expected_uid=%u mode=%04o size=%lld expected_size=%zu\n",
                path, static_cast<unsigned>(info.st_uid),
                static_cast<unsigned>(expected_owner),
                static_cast<unsigned>(info.st_mode & 0777),
                static_cast<long long>(info.st_size), length);
        close(fd);
        return false;
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, static_cast<uint8_t *>(bytes) + offset,
                             length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            fprintf(stderr,
                    "ReadSecureFileExact read failed: path=%s bytes=%zu "
                    "expected=%zu errno=%d (%s)\n",
                    path, offset, length, errno, strerror(errno));
            close(fd);
            return false;
        }
        offset += static_cast<size_t>(count);
    }
    if (close(fd) != 0) {
        fprintf(stderr, "ReadSecureFileExact close failed: path=%s errno=%d\n",
                path, errno);
        return false;
    }
    return true;
}

}  // namespace nfcf_backend
