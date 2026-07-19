#include <notify.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
        if (!nfcf_backend::ReadSecureFileExact(
                nfcf_backend::kProfileRecordPath, encoded, sizeof(encoded),
                getuid()) ||
            !nfcf::DecodeProfileRecordBytes(
                encoded, sizeof(encoded), &record) ||
            !nfcf::DecodeProfileRecord(record, &profile)) {
            fprintf(stderr, "No valid protected NFC-F profile record.\n");
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
