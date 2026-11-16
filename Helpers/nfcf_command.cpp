#include <notify.h>
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#include "CommandProtocol.hpp"
#include "BackendPaths.hpp"
#include "SecureFile.hpp"
#include "NFCFProfileRecord.hpp"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: nfcf-command <command>\n");
        return 2;
    }
    if (strcmp(argv[1], "validate-profile") == 0 ||
        strcmp(argv[1], "fingerprint-profile") == 0) {
        uint8_t encoded[nfcf::kProfileRecordEncodedSize] = {};
        nfcf::ProfileRecord record = {};
        nfcf::Profile profile = {};
        int profile_fd = open(nfcf_backend::kProfileRecordPath, O_RDONLY);
        char resolved_profile_path[PATH_MAX] = {};
        if (profile_fd < 0 && errno == ENOENT) {
            if (realpath(nfcf_backend::kProfileRecordPath,
                         resolved_profile_path) != nullptr) {
                profile_fd = open(resolved_profile_path, O_RDONLY);
                if (profile_fd < 0 && errno == ENOENT &&
                    strncmp(resolved_profile_path, "/rootfs/", 8) != 0) {
                    char rootfs_path[PATH_MAX] = {};
                    int count = snprintf(rootfs_path, sizeof(rootfs_path),
                                         "/rootfs%s", resolved_profile_path);
                    if (count > 0 &&
                        static_cast<size_t>(count) < sizeof(rootfs_path))
                        profile_fd = open(rootfs_path, O_RDONLY);
                }
            }
        }
        if (profile_fd < 0) {
            fprintf(stderr,
                    "Profile open failed: path=%s resolved=%s errno=%d (%s).\n",
                    nfcf_backend::kProfileRecordPath,
                    resolved_profile_path[0] != '\0' ? resolved_profile_path
                                                     : "(unresolved)",
                    errno, strerror(errno));
            return 1;
        }
        struct stat profile_info = {};
        bool profile_stat_ok = fstat(profile_fd, &profile_info) == 0;
        if (!profile_stat_ok) {
            fprintf(stderr, "Profile fstat failed: errno=%d (%s).\n", errno,
                    strerror(errno));
            close(profile_fd);
            return 1;
        }
        if (!S_ISREG(profile_info.st_mode) ||
            profile_info.st_uid != getuid() ||
            (profile_info.st_mode & 0777) != 0600 ||
            profile_info.st_size !=
                static_cast<off_t>(sizeof(encoded))) {
            fprintf(stderr,
                    "Profile metadata invalid: regular=%d uid=%u expected=%u "
                    "mode=%04o size=%lld expected=%zu.\n",
                    S_ISREG(profile_info.st_mode) ? 1 : 0,
                    static_cast<unsigned>(profile_info.st_uid),
                    static_cast<unsigned>(getuid()),
                    static_cast<unsigned>(profile_info.st_mode & 0777),
                    static_cast<long long>(profile_info.st_size),
                    sizeof(encoded));
            close(profile_fd);
            return 1;
        }
        ssize_t bytes_read = read(profile_fd, encoded, sizeof(encoded));
        int read_errno = errno;
        int close_result = close(profile_fd);
        if (bytes_read != static_cast<ssize_t>(sizeof(encoded)) ||
            close_result != 0) {
            fprintf(stderr,
                    "Profile read failed: bytes=%ld expected=%zu "
                    "close=%d errno=%d (%s).\n",
                    static_cast<long>(bytes_read), sizeof(encoded),
                    close_result, read_errno, strerror(read_errno));
            return 1;
        }
        if (!nfcf::DecodeProfileRecordBytes(
                encoded, sizeof(encoded), &record)) {
            fprintf(stderr,
                    "Profile format invalid: check magic, version, "
                    "checksum, block count, and zero-filled unused blocks.\n");
            return 1;
        }
        if (!nfcf::DecodeProfileRecord(record, &profile)) {
            fprintf(stderr, "Profile values are invalid.\n");
            return 1;
        }
        if (strcmp(argv[1], "fingerprint-profile") == 0) {
            uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {};
            CC_SHA256(encoded, static_cast<CC_LONG>(sizeof(encoded)), digest);
            for (uint8_t byte : digest) printf("%02x", byte);
            putchar('\n');
        }
        return 0;
    }
    nfcf_backend::Command command = {};
    if (!nfcf_backend::ParseCommandName(argv[1], &command)) {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 2;
    }
    const char *notification = nfcf_backend::CommandNotification(command);
    if (notification == nullptr) return 2;
    uint8_t nonce[16] = {};
    arc4random_buf(nonce, sizeof(nonce));
    if (!nfcf_backend::WriteCommandRequest(command, nonce)) {
        fprintf(stderr, "Could not create the protected command request.\n");
        return 1;
    }
    uint32_t status = notify_post(notification);
    if (status != NOTIFY_STATUS_OK) {
        fprintf(stderr, "notify_post failed: %u\n", status);
        return 1;
    }
    return 0;
}
