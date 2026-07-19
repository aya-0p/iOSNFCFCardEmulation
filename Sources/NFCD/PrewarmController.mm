#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <notify.h>
#import <objc/runtime.h>
#include <unistd.h>

#include "Core/BackendPaths.hpp"
#include "Core/SecureFile.hpp"
#include "IPC/CommandProtocol.hpp"

@interface NSObject (NFCFPrewarmPrivate)
+ (id)sharedHardwareManager;
- (id)driverWrapper;
- (unsigned long long)openSession:(id)owner error:(id *)error;
- (void)closeSession:(id)owner;
@end

static int gCommandToken;
static dispatch_queue_t gCommandQueue;
static BOOL gOpened;
static NSString *const kOwner = @"iOSNFCFCardEmulation";

static id object_ivar(id object, const char *name) {
    if (object == nil) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    if (ivar == NULL) return nil;
    return object_getIvar(object, ivar);
}

static void write_result(NSString *action, unsigned long long result, id error) {
    NSString *payload = [NSString stringWithFormat:
        @"action=%@\nresult=%llu\nerror=%@\npid=%d\n",
        action, result, error != nil ? [error description] : @"none", getpid()];
    (void)nfcf_backend::WriteSecureTextFile(
        nfcf_backend::kPrewarmResultPath, payload.UTF8String);
}

static void handle_close_command(void) {
    Class manager_class = objc_getClass("_NFHardwareManager");
    id manager = manager_class != Nil &&
            [manager_class respondsToSelector:@selector(sharedHardwareManager)]
        ? [manager_class sharedHardwareManager] : nil;
    dispatch_queue_t work_queue = (dispatch_queue_t)object_ivar(manager, "_workQueue");
    if (manager == nil || work_queue == NULL ||
        ![manager respondsToSelector:@selector(driverWrapper)]) {
        write_result(@"unavailable", 0, @"manager/work queue unavailable");
        return;
    }
    dispatch_async(work_queue, ^{
        @autoreleasepool {
            id wrapper = [manager driverWrapper];
            if (wrapper == nil) {
                write_result(@"unavailable", 0, @"driver wrapper unavailable");
                return;
            }
            if (![wrapper respondsToSelector:@selector(closeSession:)]) {
                write_result(@"unavailable", 0,
                             @"closeSession unavailable");
                return;
            }
            if (!gOpened) {
                write_result(@"already-closed", 1, nil);
                return;
            }
            [wrapper closeSession:kOwner];
            gOpened = NO;
            write_result(@"close", 1, nil);
        }
    });
}

static void handle_command(void) {
    Class manager_class = objc_getClass("_NFHardwareManager");
    id manager = manager_class != Nil &&
            [manager_class respondsToSelector:@selector(sharedHardwareManager)]
        ? [manager_class sharedHardwareManager] : nil;
    dispatch_queue_t work_queue = (dispatch_queue_t)object_ivar(manager, "_workQueue");
    if (manager == nil || work_queue == NULL ||
        ![manager respondsToSelector:@selector(driverWrapper)]) {
        write_result(@"unavailable", 0, @"manager/work queue unavailable");
        return;
    }

    dispatch_async(work_queue, ^{
        @autoreleasepool {
            id wrapper = [manager driverWrapper];
            if (wrapper == nil) {
                write_result(@"unavailable", 0, @"driver wrapper unavailable");
                return;
            }
            if (![wrapper respondsToSelector:@selector(openSession:error:)]) {
                write_result(@"unavailable", 0,
                             @"openSession unavailable");
                return;
            }
            if (gOpened) {
                // start is repeatable. Closing here made every second start
                // tear down the driver immediately before SetCE.
                write_result(@"already-open", 1, nil);
                return;
            }
            id error = nil;
            unsigned long long result = [wrapper openSession:kOwner error:&error];
            gOpened = result == 1;
            write_result(@"open", result, error);
        }
    });
}

static void RegisterPrewarmNotification(void) {
    @autoreleasepool {
        gCommandQueue = dispatch_queue_create("org.hoshitsugi.iosnfcfcardemulation.prewarm.queue",
                                              DISPATCH_QUEUE_SERIAL);
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kPrewarmOpen),
                                 &gCommandToken,
                                 gCommandQueue, ^(int token) {
            (void)token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kPrewarmOpen))
                handle_command();
        });
        static int close_token;
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kPrewarmClose),
                                 &close_token, gCommandQueue, ^(int token) {
            (void)token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kPrewarmClose))
                handle_close_command();
        });
    }
}

extern "C" void NFCFInitializePrewarm(void) {
    RegisterPrewarmNotification();
}
