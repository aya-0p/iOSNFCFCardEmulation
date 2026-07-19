#pragma once

#include <stddef.h>
#include <sys/types.h>

namespace nfcf_backend {

bool EnsurePrivateDirectory(const char *path);
bool WriteSecureFileAtomically(const char *path, const void *bytes,
                               size_t length);
bool WriteSecureTextFile(const char *path, const char *text);
bool ReadSecureFileExact(const char *path, void *bytes, size_t length,
                         uid_t expected_owner);

}  // namespace nfcf_backend
