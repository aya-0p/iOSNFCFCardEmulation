#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <notify.h>
#include <objc/runtime.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "NFCFProtocol.hpp"
#include "Core/BackendPaths.hpp"
#include "Core/ReadableMemory.hpp"
#include "Core/ResultWriter.hpp"
#include "IPC/CommandProtocol.hpp"
#include "Platform/NFCOffsets.hpp"

extern "C" time_t NFCFNCIGetLastFieldTime(void);
extern "C" time_t NFCFNCIGetLastActivationTime(void);
extern "C" time_t NFCFNCIGetLastResponseTime(void);

@interface NSObject (NFCFSetCEPrivate)
+ (id)sharedHardwareManager;
+ (id)hostCardEmulation;
- (id)driverWrapper;
- (id)setRoutingConfig:(id)config;
- (BOOL)restartDiscovery;
- (int)pollingType;
- (unsigned long long)hostMode;
- (unsigned long long)embeddedMode;
- (BOOL)wantsSEReader;
- (BOOL)wantsExpress;
- (unsigned long long)fieldDetect;
- (unsigned int)pollingDuration;
- (id)initPollingType:(int)pollingType
        wantsSEReader:(BOOL)wantsSEReader
         wantsExpress:(BOOL)wantsExpress
    cardEmulationType:(int)cardEmulationType
             hostMode:(unsigned long long)hostMode
         embeddedMode:(unsigned long long)embeddedMode
          fieldDetect:(unsigned long long)fieldDetect
      pollingDuration:(unsigned int)pollingDuration;
@end

typedef void *(*NFCFSetCEConfigFn)(void *driver, const void *config);
typedef uint64_t (*NFCFWaitFn)(void *mutex);
typedef void (*NFCFReleaseFn)(void *mutex);

static BOOL gActive;
// The controller retains the Type-F CE parameters after routing is stopped.
// Re-submitting the private SetCE command in the same nfcd lifetime returns
// 147, so later starts only recreate the routing configuration.
static BOOL gControllerConfigured;
static uint8_t gConfiguredIDm[8];
static uint8_t gConfiguredPMmTail[6];
static uint16_t gConfiguredSystemCode;
static id gPreviousRouting;
static id gActiveManager;

static void write_result(NSString *result) {
    NFCFWriteResult(nfcf_backend::kSetCEResultPath, result);
}

static id object_ivar(id object, const char *name) {
    if (object == nil) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    return ivar != NULL ? object_getIvar(object, ivar) : nil;
}

static void *pointer_ivar(id object, const char *name) {
    if (object == nil) return NULL;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    if (ivar == NULL) return NULL;
    ptrdiff_t offset = ivar_getOffset(ivar);
    return *(void **)((uint8_t *)(void *)object + offset);
}

static BOOL matches_bytes(const void *address, const uint8_t *expected,
                          size_t length) {
    return nfcf_backend::MatchesReadableMemory(address, expected, length);
}

static BOOL resolve_functions(NFCFSetCEConfigFn *set_ce, NFCFWaitFn *wait,
                              NFCFReleaseFn *release,
                              NSString **reason) {
    void *exported = dlsym(RTLD_DEFAULT, "NFDriverSetConfiguration");
    if (exported == NULL) {
        void *handle = dlopen("/usr/lib/libPN548_API.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (handle != NULL) exported = dlsym(handle, "NFDriverSetConfiguration");
    }
    if (exported == NULL) {
        *reason = @"NFDriverSetConfiguration-not-found";
        return NO;
    }

    Dl_info info = {};
    if (dladdr(exported, &info) == 0 || info.dli_fbase == NULL ||
        (uintptr_t)exported - (uintptr_t)info.dli_fbase !=
            nfcf_backend::nfc_offsets::kNFDriverSetConfiguration) {
        *reason = @"image-offset-mismatch";
        return NO;
    }

    uintptr_t base = (uintptr_t)info.dli_fbase;
    void *set_ce_address =
        (void *)(base + nfcf_backend::nfc_offsets::kSetCEConfig);
    void *wait_address =
        (void *)(base + nfcf_backend::nfc_offsets::kWait);
    void *release_address =
        (void *)(base + nfcf_backend::nfc_offsets::kRelease);
    static const uint8_t exported_bytes[8] = {
        0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9
    };
    static const uint8_t set_ce_bytes[8] = {
        0xff, 0xc3, 0x01, 0xd1, 0xf6, 0x57, 0x04, 0xa9
    };
    static const uint8_t wait_bytes[8] = {
        0xff, 0x03, 0x03, 0xd1, 0xfc, 0x6f, 0x06, 0xa9
    };
    static const uint8_t release_bytes[8] = {
        0xf4, 0x4f, 0xbe, 0xa9, 0xfd, 0x7b, 0x01, 0xa9
    };
    if (!matches_bytes(exported, exported_bytes, sizeof(exported_bytes)) ||
        !matches_bytes(set_ce_address, set_ce_bytes, sizeof(set_ce_bytes)) ||
        !matches_bytes(wait_address, wait_bytes, sizeof(wait_bytes)) ||
        !matches_bytes(release_address, release_bytes, sizeof(release_bytes))) {
        *reason = @"function-prologue-mismatch";
        return NO;
    }

    *set_ce = (NFCFSetCEConfigFn)set_ce_address;
    *wait = (NFCFWaitFn)wait_address;
    *release = (NFCFReleaseFn)release_address;
    return YES;
}

static id create_type_f_route(NSString **reason) {
    Class route_class = objc_getClass("NFRoutingConfig");
    if (route_class == Nil ||
        ![route_class respondsToSelector:@selector(hostCardEmulation)] ||
        ![route_class instancesRespondToSelector:
            @selector(initPollingType:wantsSEReader:wantsExpress:
                cardEmulationType:hostMode:embeddedMode:fieldDetect:
                pollingDuration:)]) {
        *reason = @"NFRoutingConfig-unavailable";
        return nil;
    }
    id host_template = [route_class hostCardEmulation];
    SEL accessors[] = {
        @selector(pollingType), @selector(wantsSEReader),
        @selector(wantsExpress), @selector(hostMode),
        @selector(embeddedMode), @selector(fieldDetect),
        @selector(pollingDuration),
    };
    for (SEL selector : accessors) {
        if (host_template == nil ||
            ![host_template respondsToSelector:selector]) {
            *reason = @"host-template-interface-unavailable";
            return nil;
        }
    }
    if ([host_template hostMode] == 0) {
        *reason = @"host-template-unavailable";
        return nil;
    }
    id route = [[route_class alloc]
        initPollingType:[host_template pollingType]
        wantsSEReader:[host_template wantsSEReader]
        wantsExpress:[host_template wantsExpress]
        cardEmulationType:4
        hostMode:[host_template hostMode]
        embeddedMode:[host_template embeddedMode]
        fieldDetect:[host_template fieldDetect]
        pollingDuration:[host_template pollingDuration]];
    if (route == nil) {
        *reason = @"route-construction-failed";
        return nil;
    }
    return [route autorelease];
}

static void clear_saved_route(void) {
    [gPreviousRouting release];
    gPreviousRouting = nil;
    [gActiveManager release];
    gActiveManager = nil;
    gActive = NO;
}

static BOOL hardware_profile_matches(const nfcf::Profile &profile) {
    return memcmp(gConfiguredIDm, profile.idm, sizeof(gConfiguredIDm)) == 0 &&
           memcmp(gConfiguredPMmTail, profile.pmm_tail,
                  sizeof(gConfiguredPMmTail)) == 0 &&
           gConfiguredSystemCode == profile.system_code;
}

static void start_card_emulation(void) {
    @autoreleasepool {
        nfcf::Profile requested_profile = {};
        if (!nfcf::CopyActiveProfile(&requested_profile)) {
            write_result(@"result=refused reason=profile-unavailable");
            return;
        }
        NSString *reason = nil;
        NFCFSetCEConfigFn set_ce = NULL;
        NFCFWaitFn wait = NULL;
        NFCFReleaseFn release = NULL;
        if (!resolve_functions(&set_ce, &wait, &release, &reason)) {
            write_result([@"result=refused reason=" stringByAppendingString:reason ?: @"unknown"]);
            return;
        }

        Class manager_class = objc_getClass("_NFHardwareManager");
        id manager = manager_class != Nil &&
                [manager_class respondsToSelector:
                    @selector(sharedHardwareManager)]
            ? [manager_class sharedHardwareManager] : nil;
        dispatch_queue_t work_queue =
            (dispatch_queue_t)object_ivar(manager, "_workQueue");
        if (manager == nil || work_queue == NULL ||
            ![manager respondsToSelector:@selector(driverWrapper)] ||
            ![manager respondsToSelector:@selector(setRoutingConfig:)]) {
            write_result(@"result=unavailable-manager");
            return;
        }

        dispatch_async(work_queue, ^{
            @autoreleasepool {
            if (gActive) {
                if (!hardware_profile_matches(requested_profile)) {
                    write_result(@"result=refused routing=active reason=hardware-profile-change-requires-stop-and-nfcd-restart");
                    return;
                }
                write_result([NSString stringWithFormat:
                    @"result=0 routing=already-active systemCode=%04X",
                    requested_profile.system_code]);
                return;
            }
            id wrapper = [manager driverWrapper];
            void *driver = pointer_ivar(wrapper, "_driver");
            if (wrapper == nil || driver == NULL) {
                write_result(@"result=unavailable-driver");
                return;
            }

            if (gControllerConfigured &&
                !hardware_profile_matches(requested_profile)) {
                write_result(@"result=refused routing=not-started reason=hardware-profile-change-requires-nfcd-restart");
                return;
            }

            if (!gControllerConfigured) {
                uint8_t config[0x60] = {};
                uint32_t type_f = 4;
                memcpy(config + 4, &type_f, sizeof(type_f));
                memcpy(config + 9, requested_profile.idm,
                       sizeof(requested_profile.idm));
                memcpy(config + 0x16, requested_profile.pmm_tail,
                        sizeof(requested_profile.pmm_tail));
                config[0x1c] =
                    static_cast<uint8_t>(requested_profile.system_code >> 8);
                config[0x1d] =
                    static_cast<uint8_t>(requested_profile.system_code & 0xff);

                void *mutex = set_ce(driver, config);
                if (mutex == NULL) {
                    write_result(@"result=no-callback-mutex");
                    return;
                }
                uint64_t raw_result = wait(mutex);
                release(mutex);
                if (raw_result != 0) {
                    write_result([NSString stringWithFormat:
                        @"result=%llu routing=not-started systemCode=%04X",
                        (unsigned long long)raw_result,
                        requested_profile.system_code]);
                    return;
                }
                memcpy(gConfiguredIDm, requested_profile.idm,
                       sizeof(gConfiguredIDm));
                memcpy(gConfiguredPMmTail, requested_profile.pmm_tail,
                       sizeof(gConfiguredPMmTail));
                gConfiguredSystemCode = requested_profile.system_code;
                gControllerConfigured = YES;
            }

            NSString *route_reason = nil;
            id route = create_type_f_route(&route_reason);
            if (route == nil) {
                write_result([@"result=failed routing=failed reason="
                    stringByAppendingString:route_reason ?: @"unknown"]);
                return;
            }

            id previous = object_ivar(manager, "_lastKnownRoutingConfig");
            [gPreviousRouting release];
            gPreviousRouting = [previous retain];
            [gActiveManager release];
            gActiveManager = [manager retain];
            id route_error = [manager setRoutingConfig:route];
            if (route_error != nil) {
                write_result([NSString stringWithFormat:
                    @"result=failed routing=failed error=%@", route_error]);
                clear_saved_route();
                return;
            }
            gActive = YES;
            write_result([NSString stringWithFormat:
                @"result=0 routing=active systemCode=%04X",
                requested_profile.system_code]);
            }
        });
    }
}

static void stop_card_emulation(void) {
    @autoreleasepool {
        id manager = gActiveManager;
        dispatch_queue_t work_queue =
            (dispatch_queue_t)object_ivar(manager, "_workQueue");
        if (!gActive || manager == nil || work_queue == NULL) {
            write_result(@"result=0 routing=already-inactive");
            return;
        }
        dispatch_async(work_queue, ^{
            @autoreleasepool {
            id route_error = gPreviousRouting != nil
                ? [manager setRoutingConfig:gPreviousRouting] : nil;
            if (route_error != nil) {
                write_result([NSString stringWithFormat:
                    @"result=stop-failed error=%@", route_error]);
                return;
            }
            clear_saved_route();
            write_result(@"result=0 routing=inactive");
            }
        });
    }
}

static void recover_card_emulation(BOOL report_result) {
    @autoreleasepool {
        Class manager_class = objc_getClass("_NFHardwareManager");
        id manager = gActiveManager ?: (manager_class != Nil
            ? [manager_class sharedHardwareManager] : nil);
        dispatch_queue_t work_queue =
            (dispatch_queue_t)object_ivar(manager, "_workQueue");
        if (!gActive || manager == nil || work_queue == NULL) {
            if (report_result)
                write_result(@"result=0 routing=inactive health=inactive");
            return;
        }
        dispatch_async(work_queue, ^{
            @autoreleasepool {
                NSString *reason = nil;
                id route = create_type_f_route(&reason);
                if (route == nil) {
                    if (report_result)
                        write_result([@"result=failed routing=stale reason="
                            stringByAppendingString:reason ?: @"unknown"]);
                    return;
                }
                id route_error = [manager setRoutingConfig:route];
                if (route_error != nil) {
                    if (report_result)
                        write_result([NSString stringWithFormat:
                            @"result=failed routing=stale error=%@", route_error]);
                    return;
                }
                BOOL restarted = [manager restartDiscovery];
                if (report_result)
                    write_result([NSString stringWithFormat:
                        @"result=%d routing=%@ health=%@", restarted ? 0 : 1,
                        restarted ? @"active" : @"stale",
                        restarted ? @"recovered" : @"restart-failed"]);
            }
        });
    }
}

static void report_card_emulation_status(void) {
    @autoreleasepool {
        id manager = gActiveManager;
        id wrapper = manager != nil ? [manager driverWrapper] : nil;
        void *driver = pointer_ivar(wrapper, "_driver");
        NSString *routing = gActive ? @"active" : @"inactive";
        NSString *health = gActive && manager != nil && driver != NULL
            ? @"configured" : (gActive ? @"stale" : @"inactive");
        time_t now = time(NULL);
        time_t field = NFCFNCIGetLastFieldTime();
        time_t activation = NFCFNCIGetLastActivationTime();
        time_t response = NFCFNCIGetLastResponseTime();
        write_result([NSString stringWithFormat:
            @"result=0 routing=%@ health=%@ configured=%d "
             "fieldAge=%lld activationAge=%lld responseAge=%lld", routing,
            health, gControllerConfigured ? 1 : 0,
            field == 0 ? -1LL : (long long)(now - field),
            activation == 0 ? -1LL : (long long)(now - activation),
            response == 0 ? -1LL : (long long)(now - response)]);
    }
}

extern "C" void NFCFRecoverRouteInternally(void) {
    recover_card_emulation(NO);
}

static void RegisterSetCENotifications(void) {
    @autoreleasepool {
        static int token;
        static int stop_token;
        static int recover_token;
        static int status_token;
        dispatch_queue_t queue = dispatch_queue_create(
            "org.hoshitsugi.iosnfcfcardemulation.setce.queue", DISPATCH_QUEUE_SERIAL);
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kSetCEStart),
                                 &token, queue,
                                 ^(int notification_token) {
            (void)notification_token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kSetCEStart))
                start_card_emulation();
        });
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kSetCEStop),
                                 &stop_token, queue,
                                 ^(int notification_token) {
            (void)notification_token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kSetCEStop))
                stop_card_emulation();
        });
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kSetCERecover),
                                 &recover_token, queue,
                                 ^(int notification_token) {
            (void)notification_token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kSetCERecover))
                recover_card_emulation(YES);
        });
        notify_register_dispatch(nfcf_backend::CommandNotification(
                                     nfcf_backend::Command::kSetCEStatus),
                                 &status_token, queue,
                                 ^(int notification_token) {
            (void)notification_token;
            if (nfcf_backend::ConsumeCommandRequest(
                    nfcf_backend::Command::kSetCEStatus))
                report_card_emulation_status();
        });
    }
}

extern "C" void NFCFInitializeSetCE(void) {
    RegisterSetCENotifications();
}
