#include <dlfcn.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "BoundedAppendLog.hpp"
#include "Core/BackendPaths.hpp"
#include "Core/NFCFProtocol.hpp"
#include "Core/ReadableMemory.hpp"
#include "Platform/NFCOffsets.hpp"

static const uint8_t kExpectedDriverPrologue[8] = {
    0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9
};

typedef void (*StackCallback)(void *stack_context, void *user_context,
                              uint32_t status);
typedef uint32_t (*ConfigRoutingTableFn)(void *stack_context, uint8_t count,
                                         const void *entries,
                                         StackCallback callback,
                                         void *user_context);
typedef uint32_t (*ConfigureDiscoveryFn)(void *stack_context, uint32_t mode,
                                         const void *configuration,
                                         StackCallback callback,
                                         void *user_context);
typedef uint32_t (*SetCEConfigParamsFn)(void *stack_context,
                                        const void *configuration,
                                        StackCallback callback,
                                        void *user_context);

typedef enum {
    kHookRoute = 0,
    kHookDiscovery = 1,
    kHookSetCE = 2,
    kHookCount = 3,
} HookKind;

typedef struct {
    HookKind kind;
    const char *name;
    const char *symbol_name;
    uintptr_t callsite_offset;
    uint8_t call_bytes[4];
    uintptr_t export_offset;
    uint8_t export_prologue[8];
    uint8_t island_bytes[12];
    uintptr_t local_stub_offset;
    uint8_t local_stub_bytes[12];
    uint8_t *callsite;
    uint8_t *island;
    uint8_t *local_stub;
    void **binding_slot;
    void *symbol;
} HookTarget;

static HookTarget gTargets[kHookCount] = {
    {
        kHookRoute, "route", "phLibNfc_Mgt_ConfigRoutingTable", 0x405c0,
        {0x33, 0xc8, 0x9b, 0x95}, 0x6e8c0,
        {0xff, 0x83, 0x01, 0xd1, 0xf8, 0x5f, 0x02, 0xa9},
        {0xd0, 0x47, 0xfe, 0xb0, 0x10, 0x02,
         0x23, 0x91, 0x00, 0x02, 0x1f, 0xd6},
        0x44a0c,
        {0x30, 0xb6, 0x0d, 0xf0, 0x10, 0x86,
         0x45, 0xf9, 0x00, 0x02, 0x1f, 0xd6},
        NULL, NULL, NULL, NULL, NULL
    },
    {
        kHookDiscovery, "discovery", "phLibNfc_Mgt_ConfigureDiscovery",
        0x402f8, {0xeb, 0xc8, 0x9b, 0x95}, 0x6ea80,
        {0xff, 0x83, 0x01, 0xd1, 0xf8, 0x5f, 0x02, 0xa9},
        {0xd0, 0x47, 0xfe, 0xb0, 0x10, 0x02,
         0x2a, 0x91, 0x00, 0x02, 0x1f, 0xd6},
        0x44a24,
        {0x30, 0xb6, 0x0d, 0xf0, 0x10, 0x8e,
         0x45, 0xf9, 0x00, 0x02, 0x1f, 0xd6},
        NULL, NULL, NULL, NULL, NULL
    },
    {
        kHookSetCE, "setce", "phLibNfc_Mgt_SetCE_ConfigParams", 0x124c4,
        {0xab, 0x80, 0x9c, 0x95}, 0x1da74,
        {0xff, 0x03, 0x01, 0xd1, 0xf6, 0x57, 0x01, 0xa9},
        {0x50, 0x45, 0xfe, 0x90, 0x10, 0xd2,
         0x29, 0x91, 0x00, 0x02, 0x1f, 0xd6},
        0x44af0,
        {0x30, 0xb6, 0x0d, 0xf0, 0x10, 0xd2,
         0x45, 0xf9, 0x00, 0x02, 0x1f, 0xd6},
        NULL, NULL, NULL, NULL, NULL
    },
};

typedef struct {
    StackCallback callback;
    void *user_context;
    uint32_t sequence;
    HookKind kind;
} ObservedCallback;

static ConfigRoutingTableFn gOriginalRoute;
static ConfigureDiscoveryFn gOriginalDiscovery;
static SetCEConfigParamsFn gOriginalSetCE;
static uint32_t gRouteSequence;
static uint32_t gDiscoverySequence;
static uint32_t gSetCESequence;
static NFCFBoundedAppendLog gLog = NFCF_BOUNDED_APPEND_LOG_INITIALIZER(
    nfcf_backend::kStackObserverResultPath);

static void append_line(const char *format, ...) {
    char buffer[4096];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(buffer, sizeof(buffer) - 2, format, arguments);
    va_end(arguments);
    if (length < 0) return;
    size_t used = (size_t)length;
    if (used > sizeof(buffer) - 2) used = sizeof(buffer) - 2;
    buffer[used++] = '\n';
    NFCFWriteBoundedAppendLog(&gLog, buffer, used);
}

static const char *hook_name(HookKind kind) {
    switch (kind) {
        case kHookRoute: return "route";
        case kHookDiscovery: return "discovery";
        case kHookSetCE: return "setce";
        default: return "unknown";
    }
}

static void observed_callback(void *stack_context, void *opaque,
                              uint32_t status) {
    ObservedCallback *observed = (ObservedCallback *)opaque;
    if (observed == NULL) return;
    append_line("event=%s-callback seq=%u status=0x%02X",
                hook_name(observed->kind), observed->sequence,
                status & 0xff);
    StackCallback callback = observed->callback;
    void *user_context = observed->user_context;
    free(observed);
    if (callback != NULL) callback(stack_context, user_context, status);
}

static ObservedCallback *make_observed_callback(StackCallback callback,
                                                 void *user_context,
                                                 uint32_t sequence,
                                                 HookKind kind) {
    ObservedCallback *observed =
        (ObservedCallback *)calloc(1, sizeof(ObservedCallback));
    if (observed == NULL) return NULL;
    observed->callback = callback;
    observed->user_context = user_context;
    observed->sequence = sequence;
    observed->kind = kind;
    return observed;
}

static void release_if_not_pending(ObservedCallback *observed,
                                   uint32_t result) {
    // 0x0D is this stack's asynchronous/pending result. No completion
    // callback owns the wrapper for immediate results.
    if ((result & 0xff) != 0x0d) free(observed);
}

static uint32_t observed_config_routing_table(
    void *stack_context, uint8_t count, const void *entries,
    StackCallback callback, void *user_context) {
    uint32_t sequence = __sync_add_and_fetch(&gRouteSequence, 1);
    append_line("event=route-call seq=%u count=%u", sequence, count);

    const uint8_t *bytes = (const uint8_t *)entries;
    uint8_t safe_count = count > 11 ? 11 : count;
    for (uint8_t index = 0; bytes != NULL && index < safe_count; ++index) {
        const uint8_t *entry = bytes + (size_t)index * 0x28;
        uint32_t type = 0;
        uint32_t value = 0;
        memcpy(&type, entry + 8, sizeof(type));
        memcpy(&value, entry + 0x10, sizeof(value));
        append_line("entry=%u type=%u flags=0x%02X value=%u auxLen=%u",
                    index, type, entry[0x0c], value, entry[0x20]);
    }

    ObservedCallback *observed = make_observed_callback(
        callback, user_context, sequence, kHookRoute);
    if (observed == NULL) {
        append_line("event=route-observer-allocation-failed seq=%u",
                    sequence);
        return gOriginalRoute(stack_context, count, entries, callback,
                              user_context);
    }
    uint32_t result = gOriginalRoute(stack_context, count, entries,
                                     observed_callback, observed);
    append_line("event=route-return seq=%u status=0x%02X", sequence,
                result & 0xff);
    release_if_not_pending(observed, result);
    return result;
}

static uint32_t observed_configure_discovery(
    void *stack_context, uint32_t mode, const void *configuration,
    StackCallback callback, void *user_context) {
    uint32_t sequence = __sync_add_and_fetch(&gDiscoverySequence, 1);
    const uint8_t *bytes = (const uint8_t *)configuration;
    uint32_t technology_mask = 0;
    uint32_t tail_mode = 0;
    if (bytes != NULL) {
        memcpy(&technology_mask, bytes, sizeof(technology_mask));
        memcpy(&tail_mode, bytes + 0x58, sizeof(tail_mode));
    }
    append_line("event=discovery-call seq=%u mode=%u techMask=0x%08X "
                "byte9=0x%02X byteC=0x%02X byte54=0x%02X tailMode=%u "
                "config=redacted", sequence, mode, technology_mask,
                bytes == NULL ? 0 : bytes[9],
                bytes == NULL ? 0 : bytes[0x0c],
                bytes == NULL ? 0 : bytes[0x54], tail_mode);

    ObservedCallback *observed = make_observed_callback(
        callback, user_context, sequence, kHookDiscovery);
    if (observed == NULL) {
        append_line("event=discovery-observer-allocation-failed seq=%u",
                    sequence);
        return gOriginalDiscovery(stack_context, mode, configuration,
                                  callback, user_context);
    }
    uint32_t result = gOriginalDiscovery(stack_context, mode, configuration,
                                         observed_callback, observed);
    append_line("event=discovery-return seq=%u status=0x%02X", sequence,
                result & 0xff);
    release_if_not_pending(observed, result);
    return result;
}

static uint32_t observed_setce_config_params(
    void *stack_context, const void *configuration, StackCallback callback,
    void *user_context) {
    uint32_t sequence = __sync_add_and_fetch(&gSetCESequence, 1);
    const uint8_t *bytes = (const uint8_t *)configuration;
    uint32_t type = 0;
    if (bytes != NULL) memcpy(&type, bytes + 4, sizeof(type));
    nfcf::Profile active_profile = {};
    uint8_t system_code[2] = {};
    const int has_profile = nfcf::CopyActiveProfile(&active_profile);
    if (has_profile) {
        system_code[0] =
            static_cast<uint8_t>(active_profile.system_code >> 8);
        system_code[1] =
            static_cast<uint8_t>(active_profile.system_code & 0xff);
    }
    int is_emulated = bytes != NULL && type == 4 &&
        has_profile &&
        memcmp(bytes + 9, active_profile.idm, sizeof(active_profile.idm)) == 0 &&
        memcmp(bytes + 0x16, active_profile.pmm_tail,
               sizeof(active_profile.pmm_tail)) == 0 &&
        memcmp(bytes + 0x1c, system_code, sizeof(system_code)) == 0;
    if (is_emulated) {
        append_line("event=setce-call seq=%u emulated=yes type=%u "
                    "identity=redacted systemCode=%04X",
                    sequence, type, active_profile.system_code);
    } else {
        // Do not log identifiers belonging to unrelated system routes.
        append_line("event=setce-call seq=%u emulated=no type=%u",
                    sequence, type);
    }

    ObservedCallback *observed = make_observed_callback(
        callback, user_context, sequence, kHookSetCE);
    if (observed == NULL) {
        append_line("event=setce-observer-allocation-failed seq=%u",
                    sequence);
        return gOriginalSetCE(stack_context, configuration, callback,
                              user_context);
    }
    uint32_t result = gOriginalSetCE(stack_context, configuration,
                                     observed_callback, observed);
    append_line("event=setce-return seq=%u status=0x%02X", sequence,
                result & 0xff);
    release_if_not_pending(observed, result);
    return result;
}

static int64_t sign_extend_21(uint64_t value) {
    return (int64_t)(value << 43) >> 43;
}

static int64_t sign_extend_26(uint64_t value) {
    return (int64_t)(value << 38) >> 38;
}

static uint8_t *decode_bl_target(uint8_t *callsite) {
    uint32_t instruction = 0;
    memcpy(&instruction, callsite, sizeof(instruction));
    int64_t displacement = sign_extend_26(instruction & 0x03ffffff) * 4;
    return callsite + displacement;
}

static uint8_t *decode_adrp_add_target(uint8_t *stub) {
    uint32_t adrp = 0;
    uint32_t add = 0;
    memcpy(&adrp, stub, sizeof(adrp));
    memcpy(&add, stub + 4, sizeof(add));
    uint64_t immlo = (adrp >> 29) & 0x3;
    uint64_t immhi = (adrp >> 5) & 0x7ffff;
    int64_t page_delta = sign_extend_21((immhi << 2) | immlo) * 4096;
    uintptr_t pc_page = (uintptr_t)stub & ~(uintptr_t)0xfff;
    uintptr_t target_page = (uintptr_t)((int64_t)pc_page + page_delta);
    uintptr_t byte_offset = (add >> 10) & 0xfff;
    if ((add >> 22) & 1) byte_offset <<= 12;
    return (uint8_t *)(target_page + byte_offset);
}

static void **decode_adrp_ldr_slot(uint8_t *stub) {
    uint32_t adrp = 0;
    uint32_t ldr = 0;
    memcpy(&adrp, stub, sizeof(adrp));
    memcpy(&ldr, stub + 4, sizeof(ldr));
    uint64_t immlo = (adrp >> 29) & 0x3;
    uint64_t immhi = (adrp >> 5) & 0x7ffff;
    int64_t page_delta = sign_extend_21((immhi << 2) | immlo) * 4096;
    uintptr_t pc_page = (uintptr_t)stub & ~(uintptr_t)0xfff;
    uintptr_t target_page = (uintptr_t)((int64_t)pc_page + page_delta);
    uintptr_t byte_offset = ((ldr >> 10) & 0xfff) * sizeof(void *);
    return (void **)(target_page + byte_offset);
}

static int replace_code_word(uint8_t *address, uint32_t expected,
                             uint32_t replacement) {
    uint32_t current = 0;
    memcpy(&current, address, sizeof(current));
    if (current != expected) return -1;
    vm_size_t page_size = 0;
    if (host_page_size(mach_host_self(), &page_size) != KERN_SUCCESS ||
        page_size == 0) return -2;
    vm_address_t page = (vm_address_t)((uintptr_t)address &
        ~((uintptr_t)page_size - 1));
    kern_return_t write_kr = vm_protect(
        mach_task_self(), page, page_size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (write_kr != KERN_SUCCESS) return -(100 + write_kr);
    memcpy(address, &replacement, sizeof(replacement));
    sys_icache_invalidate(address, sizeof(replacement));
    kern_return_t restore_kr = vm_protect(
        mach_task_self(), page, page_size, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    if (restore_kr != KERN_SUCCESS) return -(200 + restore_kr);
    memcpy(&current, address, sizeof(current));
    return current == replacement ? 0 : -3;
}

static int encode_bl(uint8_t *callsite, uint8_t *target,
                     uint32_t *instruction) {
    intptr_t displacement = target - callsite;
    if ((displacement & 3) != 0) return -1;
    int64_t words = displacement / 4;
    if (words < -(1LL << 25) || words >= (1LL << 25)) return -2;
    *instruction = 0x94000000 | ((uint32_t)words & 0x03ffffff);
    return 0;
}

static int replace_pointer(void **slot, void *expected, void *replacement) {
    void *current = NULL;
    memcpy(&current, slot, sizeof(current));
    if (current != expected) return -1;
    vm_size_t page_size = 0;
    if (host_page_size(mach_host_self(), &page_size) != KERN_SUCCESS ||
        page_size == 0) return -2;
    vm_address_t page = (vm_address_t)((uintptr_t)slot &
        ~((uintptr_t)page_size - 1));
    kern_return_t write_kr = vm_protect(
        mach_task_self(), page, page_size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (write_kr != KERN_SUCCESS) return -(100 + write_kr);
    memcpy(slot, &replacement, sizeof(replacement));
    kern_return_t restore_kr = vm_protect(
        mach_task_self(), page, page_size, FALSE, VM_PROT_READ);
    if (restore_kr != KERN_SUCCESS) return -(200 + restore_kr);
    memcpy(&current, slot, sizeof(current));
    return current == replacement ? 0 : -3;
}

static void *replacement_for_kind(HookKind kind) {
    switch (kind) {
        case kHookRoute: return (void *)observed_config_routing_table;
        case kHookDiscovery: return (void *)observed_configure_discovery;
        case kHookSetCE: return (void *)observed_setce_config_params;
        default: return NULL;
    }
}

static int validate_target(HookTarget *target, uint8_t *driver_base,
                           void *nfc_handle) {
    uint8_t *callsite = driver_base + target->callsite_offset;
    if (!nfcf_backend::MatchesReadableMemory(
            callsite, target->call_bytes, sizeof(target->call_bytes)))
        return -1;
    void *symbol = dlsym(RTLD_DEFAULT, target->symbol_name);
    if (symbol == NULL && nfc_handle != NULL)
        symbol = dlsym(nfc_handle, target->symbol_name);
    Dl_info info = {};
    if (symbol == NULL || dladdr(symbol, &info) == 0 ||
        info.dli_fbase == NULL ||
        (uintptr_t)symbol - (uintptr_t)info.dli_fbase !=
            target->export_offset ||
        !nfcf_backend::MatchesReadableMemory(
            symbol, target->export_prologue,
            sizeof(target->export_prologue)))
        return -2;
    uint8_t *island = decode_bl_target(callsite);
    if (!nfcf_backend::MatchesReadableMemory(
            island, target->island_bytes, sizeof(target->island_bytes)) ||
        decode_adrp_add_target(island) != symbol)
        return -3;

    uint8_t *local_stub = driver_base + target->local_stub_offset;
    if (!nfcf_backend::MatchesReadableMemory(
            local_stub, target->local_stub_bytes,
            sizeof(target->local_stub_bytes)))
        return -4;
    void **binding_slot = decode_adrp_ldr_slot(local_stub);
    if (!nfcf_backend::IsReadableMemory(binding_slot,
                                         sizeof(*binding_slot)))
        return -5;
    void *bound_target = NULL;
    memcpy(&bound_target, binding_slot, sizeof(bound_target));
    if (bound_target != symbol) return -6;

    target->callsite = callsite;
    target->symbol = symbol;
    target->island = island;
    target->local_stub = local_stub;
    target->binding_slot = binding_slot;
    return 0;
}

extern "C" void NFCFInitializeStackObserver(void) {
    NFCFResetBoundedAppendLog(&gLog);

    void *driver_export = dlsym(RTLD_DEFAULT, "NFDriverSetConfiguration");
    Dl_info driver_info = {};
    if (driver_export == NULL || dladdr(driver_export, &driver_info) == 0 ||
        driver_info.dli_fbase == NULL ||
        (uintptr_t)driver_export - (uintptr_t)driver_info.dli_fbase !=
            nfcf_backend::nfc_offsets::kNFDriverSetConfiguration ||
        !nfcf_backend::MatchesReadableMemory(
            driver_export, kExpectedDriverPrologue,
            sizeof(kExpectedDriverPrologue))) {
        append_line("observer=refused reason=driver-image-mismatch");
        return;
    }

    void *nfc_handle = dlopen("/usr/lib/libNFC_Comet.dylib",
                              RTLD_LAZY | RTLD_LOCAL);
    for (size_t index = 0; index < kHookCount; ++index) {
        int result = validate_target(&gTargets[index],
                                     (uint8_t *)driver_info.dli_fbase,
                                     nfc_handle);
        if (result != 0) {
            append_line("observer=refused reason=%s-validation code=%d",
                        gTargets[index].name, result);
            return;
        }
    }

    gOriginalRoute = (ConfigRoutingTableFn)gTargets[kHookRoute].symbol;
    gOriginalDiscovery =
        (ConfigureDiscoveryFn)gTargets[kHookDiscovery].symbol;
    gOriginalSetCE = (SetCEConfigParamsFn)gTargets[kHookSetCE].symbol;

    size_t patched_callsites = 0;
    size_t patched_bindings = 0;
    int result = 0;
    const char *failed_name = "unknown";
    for (; patched_callsites < kHookCount; ++patched_callsites) {
        HookTarget *target = &gTargets[patched_callsites];
        uint32_t original = 0;
        uint32_t replacement = 0;
        memcpy(&original, target->call_bytes, sizeof(original));
        result = encode_bl(target->callsite, target->local_stub,
                           &replacement);
        if (result == 0)
            result = replace_code_word(target->callsite, original,
                                       replacement);
        if (result != 0) {
            failed_name = target->name;
            break;
        }
    }
    if (result == 0) {
        for (; patched_bindings < kHookCount; ++patched_bindings) {
            HookTarget *target = &gTargets[patched_bindings];
            result = replace_pointer(
                target->binding_slot, target->symbol,
                replacement_for_kind(target->kind));
            if (result != 0) {
                failed_name = target->name;
                break;
            }
        }
    }
    if (result != 0) {
        while (patched_bindings > 0) {
            --patched_bindings;
            HookTarget *target = &gTargets[patched_bindings];
            (void)replace_pointer(
                target->binding_slot,
                replacement_for_kind(target->kind), target->symbol);
        }
        while (patched_callsites > 0) {
            --patched_callsites;
            HookTarget *target = &gTargets[patched_callsites];
            uint32_t original = 0;
            uint32_t replacement = 0;
            memcpy(&original, target->call_bytes, sizeof(original));
            if (encode_bl(target->callsite, target->local_stub,
                          &replacement) == 0)
                (void)replace_code_word(target->callsite, replacement,
                                        original);
        }
        gOriginalRoute = NULL;
        gOriginalDiscovery = NULL;
        gOriginalSetCE = NULL;
        append_line("observer=failed reason=%s-local-route-patch code=%d",
                    failed_name, result);
        return;
    }

    append_line("observer=installed method=guarded-local-stubs hooks=3 "
                "routeStub=0x%lx discoveryStub=0x%lx setceStub=0x%lx",
                (unsigned long)gTargets[kHookRoute].local_stub_offset,
                (unsigned long)gTargets[kHookDiscovery].local_stub_offset,
                (unsigned long)gTargets[kHookSetCE].local_stub_offset);
}
