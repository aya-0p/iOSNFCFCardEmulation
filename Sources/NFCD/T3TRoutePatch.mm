#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <notify.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "Core/BackendPaths.hpp"
#include "Core/ReadableMemory.hpp"
#include "Core/ResultWriter.hpp"
#include "IPC/CommandProtocol.hpp"
#include "Platform/NFCOffsets.hpp"

// mov w9, #4 (ISO-DEP) -> mov w9, #3 (T3T).
static const uint8_t kOriginalInstruction[4] = {0x89, 0x00, 0x80, 0x52};
static const uint8_t kPatchedInstruction[4] = {0x69, 0x00, 0x80, 0x52};
static const uint8_t kExpectedExportPrologue[8] = {
    0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9
};

static void write_result(NSString *result) {
    NFCFWriteResult(nfcf_backend::kRoutePatchResultPath, result);
}

static BOOL resolve_target(uint8_t **target, NSString **reason) {
    void *exported = dlsym(RTLD_DEFAULT, "NFDriverSetConfiguration");
    if (exported == NULL) {
        void *handle = dlopen("/usr/lib/libPN548_API.dylib",
                              RTLD_LAZY | RTLD_LOCAL);
        if (handle != NULL) {
            exported = dlsym(handle, "NFDriverSetConfiguration");
        }
    }
    if (exported == NULL) {
        *reason = @"NFDriverSetConfiguration-not-found";
        return NO;
    }

    Dl_info info = {};
    if (dladdr(exported, &info) == 0 || info.dli_fbase == NULL) {
        *reason = @"image-base-not-found";
        return NO;
    }
    uintptr_t base = (uintptr_t)info.dli_fbase;
    if ((uintptr_t)exported - base !=
        nfcf_backend::nfc_offsets::kNFDriverSetConfiguration) {
        *reason = @"export-offset-mismatch";
        return NO;
    }
    if (!nfcf_backend::MatchesReadableMemory(
            exported, kExpectedExportPrologue,
            sizeof(kExpectedExportPrologue))) {
        *reason = @"export-prologue-mismatch";
        return NO;
    }

    *target = (uint8_t *)(
        base + nfcf_backend::nfc_offsets::kHostProtocolInstruction);
    if (!nfcf_backend::IsReadableMemory(*target, 4)) {
        *reason = @"patch-address-unreadable";
        return NO;
    }
    return YES;
}

static BOOL write_instruction(uint8_t *target, const uint8_t bytes[4],
                              NSString **reason) {
    vm_size_t page_size = 0;
    kern_return_t page_kr = host_page_size(mach_host_self(), &page_size);
    if (page_kr != KERN_SUCCESS || page_size == 0) {
        *reason = [NSString stringWithFormat:@"host-page-size-failed kr=%d",
                                             page_kr];
        return NO;
    }

    vm_address_t page =
        (vm_address_t)((uintptr_t)target & ~((uintptr_t)page_size - 1));
    kern_return_t write_kr = vm_protect(
        mach_task_self(), page, page_size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    int mprotect_error = 0;
    if (write_kr != KERN_SUCCESS) {
        if (mprotect((void *)(uintptr_t)page, page_size,
                     PROT_READ | PROT_WRITE) != 0) {
            mprotect_error = errno;
            *reason = [NSString stringWithFormat:
                @"make-writable-failed kr=%d errno=%d", write_kr,
                mprotect_error];
            return NO;
        }
    }

    memcpy(target, bytes, 4);
    sys_icache_invalidate(target, 4);

    kern_return_t restore_kr = vm_protect(
        mach_task_self(), page, page_size, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    if (restore_kr != KERN_SUCCESS &&
        mprotect((void *)(uintptr_t)page, page_size,
                 PROT_READ | PROT_EXEC) != 0) {
        *reason = [NSString stringWithFormat:
            @"restore-rx-failed kr=%d errno=%d", restore_kr, errno];
        return NO;
    }
    if (memcmp(target, bytes, 4) != 0) {
        *reason = @"post-write-verification-failed";
        return NO;
    }
    return YES;
}

static void handle_patch(BOOL restore) {
    @autoreleasepool {
        uint8_t *target = NULL;
        NSString *reason = nil;
        if (!resolve_target(&target, &reason)) {
            write_result([@"result=refused reason="
                stringByAppendingString:reason ?: @"unknown"]);
            return;
        }

        const uint8_t *from = restore ? kPatchedInstruction
                                      : kOriginalInstruction;
        const uint8_t *to = restore ? kOriginalInstruction
                                    : kPatchedInstruction;
        if (memcmp(target, to, 4) == 0) {
            write_result(restore
                ? @"result=0 state=already-original protocol=ISO-DEP"
                : @"result=0 state=already-patched protocol=T3T");
            return;
        }
        if (memcmp(target, from, 4) != 0) {
            write_result([NSString stringWithFormat:
                @"result=refused reason=instruction-mismatch bytes=%02X%02X%02X%02X",
                target[0], target[1], target[2], target[3]]);
            return;
        }
        if (!write_instruction(target, to, &reason)) {
            write_result([@"result=failed reason="
                stringByAppendingString:reason ?: @"unknown"]);
            return;
        }
        write_result(restore
            ? @"result=0 state=restored protocol=ISO-DEP"
            : @"result=0 state=patched protocol=T3T");
    }
}

extern "C" void NFCFInitializeT3TRoutePatch(void) {
    @autoreleasepool {
        static int patch_token;
        static int restore_token;
        dispatch_queue_t queue = dispatch_queue_create(
            "org.hoshitsugi.iosnfcfcardemulation.t3troute.queue", DISPATCH_QUEUE_SERIAL);
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kT3TPatch),
                                 &patch_token, queue,
                                 ^(int notification_token) {
            (void)notification_token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kT3TPatch))
                handle_patch(NO);
        });
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kT3TRestore),
                                 &restore_token, queue,
                                 ^(int notification_token) {
            (void)notification_token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kT3TRestore))
                handle_patch(YES);
        });
    }
}
