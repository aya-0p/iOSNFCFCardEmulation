#include "../Sources/Core/SecureFile.hpp"
#include "../Sources/IPC/CommandProtocol.hpp"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int main() {
    char directory[] = "/tmp/iosnfcf-command-test.XXXXXX";
    assert(mkdtemp(directory) != nullptr);
    assert(chmod(directory, 0700) == 0);
    assert(nfcf_backend::EnsurePrivateDirectory(directory));

    char request_path[PATH_MAX] = {};
    snprintf(request_path, sizeof(request_path), "%s/request", directory);
    const uint8_t nonce[16] = {0, 1, 2, 3, 4, 5, 6, 7,
                               8, 9, 10, 11, 12, 13, 14, 15};
    assert(nfcf_backend::WriteCommandRequestAtPath(
        request_path, nfcf_backend::Command::kSetCEStart, nonce));
    struct stat info = {};
    assert(lstat(request_path, &info) == 0);
    assert(S_ISREG(info.st_mode));
    assert((info.st_mode & 0777) == 0600);
    assert(nfcf_backend::ConsumeCommandRequestAtPath(
        request_path, nfcf_backend::Command::kSetCEStart,
        static_cast<uint64_t>(time(nullptr))));
    assert(access(request_path, F_OK) != 0);
    assert(!nfcf_backend::ConsumeCommandRequestAtPath(
        request_path, nfcf_backend::Command::kSetCEStart,
        static_cast<uint64_t>(time(nullptr))));

    assert(nfcf_backend::WriteCommandRequestAtPath(
        request_path, nfcf_backend::Command::kSetCEStop, nonce));
    assert(!nfcf_backend::ConsumeCommandRequestAtPath(
        request_path, nfcf_backend::Command::kSetCEStart,
        static_cast<uint64_t>(time(nullptr))));

    char secure_path[PATH_MAX] = {};
    snprintf(secure_path, sizeof(secure_path), "%s/result", directory);
    const char payload[] = "result=0\n";
    assert(nfcf_backend::WriteSecureFileAtomically(
        secure_path, payload, sizeof(payload)));
    char loaded[sizeof(payload)] = {};
    assert(nfcf_backend::ReadSecureFileExact(
        secure_path, loaded, sizeof(loaded), getuid()));
    assert(memcmp(payload, loaded, sizeof(payload)) == 0);

    assert(unlink(secure_path) == 0);
    assert(rmdir(directory) == 0);
    puts("command_protocol_test: PASS");
    return 0;
}
