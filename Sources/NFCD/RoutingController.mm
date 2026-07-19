#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <notify.h>
#include <objc/runtime.h>
#include <unistd.h>

#include "Core/BackendPaths.hpp"
#include "Core/ResultWriter.hpp"
#include "IPC/CommandProtocol.hpp"

@interface NSObject (NFCFRoutingOffPrivate)
+ (id)sharedHardwareManager;
+ (id)routingOff;
- (id)setRoutingConfig:(id)config;
@end

static BOOL gRoutingDisabled;
static id gPreviousRouting;
static id gRoutingManager;

static id object_ivar(id object, const char *name) {
    if (object == nil) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    return ivar != NULL ? object_getIvar(object, ivar) : nil;
}

static void write_result(NSString *result) {
    NFCFWriteResult(nfcf_backend::kRoutingResultPath, result);
}

static void set_routing_off(void) {
    @autoreleasepool {
        Class manager_class = objc_getClass("_NFHardwareManager");
        Class route_class = objc_getClass("NFRoutingConfig");
        id manager = manager_class != Nil &&
                [manager_class respondsToSelector:@selector(sharedHardwareManager)]
            ? [manager_class sharedHardwareManager] : nil;
        dispatch_queue_t work_queue =
            (dispatch_queue_t)object_ivar(manager, "_workQueue");
        id route = route_class != Nil &&
                [route_class respondsToSelector:@selector(routingOff)]
            ? [route_class routingOff] : nil;
        if (manager == nil || work_queue == NULL || route == nil ||
            ![manager respondsToSelector:@selector(setRoutingConfig:)]) {
            write_result(@"result=unavailable-manager-or-route");
            return;
        }

        dispatch_async(work_queue, ^{
            @autoreleasepool {
            if (gRoutingDisabled) {
                write_result(@"result=0 routing=already-off");
                return;
            }
            id previous = object_ivar(manager, "_lastKnownRoutingConfig");
            if (previous == nil) {
                write_result(@"result=failed reason=previous-route-unavailable");
                return;
            }
            id error = [manager setRoutingConfig:route];
            if (error != nil) {
                write_result([NSString stringWithFormat:
                    @"result=failed error=%@", error]);
                return;
            }
            [gPreviousRouting release];
            gPreviousRouting = [previous retain];
            [gRoutingManager release];
            gRoutingManager = [manager retain];
            gRoutingDisabled = YES;
            write_result(@"result=0 routing=off");
            }
        });
    }
}

static void restore_routing(void) {
    @autoreleasepool {
        id manager = gRoutingManager;
        dispatch_queue_t work_queue =
            (dispatch_queue_t)object_ivar(manager, "_workQueue");
        if (!gRoutingDisabled) {
            write_result(@"result=0 routing=already-restored");
            return;
        }
        if (manager == nil || work_queue == NULL || gPreviousRouting == nil) {
            write_result(@"result=failed reason=saved-route-unavailable");
            return;
        }
        dispatch_async(work_queue, ^{
            @autoreleasepool {
                id error = [manager setRoutingConfig:gPreviousRouting];
                if (error != nil) {
                    write_result([NSString stringWithFormat:
                        @"result=failed error=%@", error]);
                    return;
                }
                [gPreviousRouting release];
                gPreviousRouting = nil;
                [gRoutingManager release];
                gRoutingManager = nil;
                gRoutingDisabled = NO;
                write_result(@"result=0 routing=restored");
            }
        });
    }
}

static void RegisterRoutingOffNotification(void) {
    @autoreleasepool {
        static int token;
        dispatch_queue_t queue = dispatch_queue_create(
            "org.hoshitsugi.iosnfcfcardemulation.routing.queue", DISPATCH_QUEUE_SERIAL);
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kRoutingOff),
                                 &token, queue,
                                 ^(int notification_token) {
            (void)notification_token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kRoutingOff))
                set_routing_off();
        });
        static int restore_token;
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kRoutingRestore),
                                 &restore_token, queue,
                                 ^(int notification_token) {
            (void)notification_token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kRoutingRestore))
                restore_routing();
        });
    }
}

extern "C" void NFCFInitializeRouting(void) {
    RegisterRoutingOffNotification();
}
