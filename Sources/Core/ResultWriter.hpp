#pragma once

#import <Foundation/Foundation.h>

#include "BackendPaths.hpp"
#include "SecureFile.hpp"
#include <unistd.h>

static inline void NFCFWriteResult(const char *path, NSString *result) {
    if (path == nullptr || result == nil) return;
    NSString *payload = [NSString stringWithFormat:@"%@ pid=%d\n", result,
                                                    getpid()];
    (void)nfcf_backend::WriteSecureTextFile(path, payload.UTF8String);
}
