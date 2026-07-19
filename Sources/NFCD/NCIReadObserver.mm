#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <notify.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <atomic>

#include "NFCFProtocol.hpp"
#include "BoundedAppendLog.hpp"
#include "Core/BackendPaths.hpp"
#include "Core/ReadableMemory.hpp"
#include "Core/SecureFile.hpp"
#include "Platform/NFCOffsets.hpp"

static const char *kTransmitNotification =
    "org.hoshitsugi.iosnfcfcardemulation.event.transmit";
static std::atomic<uint32_t> gActivationGeneration{0};
static std::atomic<time_t> gLastRecoverPost{0};
static std::atomic<time_t> gLastFieldAt{0};
static std::atomic<time_t> gLastActivationAt{0};
static std::atomic<time_t> gLastResponseAt{0};
static dispatch_source_t gRecoverTimer;
static std::atomic<uint32_t> gRecoverGeneration{0};

extern "C" void NFCFRecoverRouteInternally(void);
extern "C" time_t NFCFNCIGetLastFieldTime(void) {
    return gLastFieldAt.load(std::memory_order_relaxed);
}
extern "C" time_t NFCFNCIGetLastActivationTime(void) {
    return gLastActivationAt.load(std::memory_order_relaxed);
}
extern "C" time_t NFCFNCIGetLastResponseTime(void) {
    return gLastResponseAt.load(std::memory_order_relaxed);
}
static const uint8_t kExpectedLibNFCPrologue[8] = {
    0xff, 0x83, 0x01, 0xd1, 0xf8, 0x5f, 0x02, 0xa9
};
static const uint8_t kExpectedTmlReadPrologue[8] = {
    0xff, 0x03, 0x03, 0xd1, 0xf6, 0x57, 0x09, 0xa9
};
static const uint8_t kExpectedTmlWritePrologue[8] = {
    0xff, 0x43, 0x03, 0xd1, 0xf8, 0x5f, 0x09, 0xa9
};
static const uint8_t kExpectedTmlReadLocalStub[12] = {
    0xb0, 0x34, 0x0c, 0x90, 0x10, 0xe6,
    0x46, 0xf9, 0x00, 0x02, 0x1f, 0xd6
};
static const uint8_t kExpectedTmlReadIsland[12] = {
    0xf0, 0xa4, 0xfe, 0xb0, 0x10, 0x22,
    0x37, 0x91, 0x00, 0x02, 0x1f, 0xd6
};
typedef struct {
    uintptr_t offset;
    uint8_t expected[4];
} ReadCallsite;

static const ReadCallsite kReadCallsites[] = {
    {0x001a18, {0x85, 0x8a, 0xde, 0x94}},
    {0x0b67e4, {0x12, 0xb7, 0xdb, 0x94}},
    {0x0b6a68, {0x71, 0xb6, 0xdb, 0x94}},
    {0x0b6afc, {0x4c, 0xb6, 0xdb, 0x94}},
    {0x0b6cbc, {0xdc, 0xb5, 0xdb, 0x94}},
    {0x0b88e8, {0xd1, 0xae, 0xdb, 0x94}},
    {0x0b8a14, {0x86, 0xae, 0xdb, 0x94}},
    {0x0b8af4, {0x4e, 0xae, 0xdb, 0x94}},
    {0x0b9914, {0xc6, 0xaa, 0xdb, 0x94}},
};

typedef struct {
    uint32_t status;
    uint32_t reserved;
    const uint8_t *buffer;
    uint16_t length;
} TmlTransactionInfo;

typedef void (*TmlReadCallback)(void *user_context,
                                TmlTransactionInfo *information);
typedef uint32_t (*TmlReadFn)(void *tml_context, uint8_t *buffer,
                              uint16_t length, TmlReadCallback callback,
                              void *user_context);
typedef void (*TmlWriteCallback)(void *user_context,
                                 TmlTransactionInfo *information);
typedef uint32_t (*TmlWriteFn)(void *tml_context, const uint8_t *buffer,
                               uint16_t length, TmlWriteCallback callback,
                               void *user_context);

typedef struct {
    TmlReadCallback callback;
    void *user_context;
    void *tml_context;
    const uint8_t *request_buffer;
    uint16_t request_length;
} ObservedReadCallback;

static TmlReadFn gOriginalRead;
static TmlWriteFn gEmulatedWrite;
static uint32_t gSequence;
static uint32_t gFieldOnCount;
static uint32_t gFieldOffCount;
static uint32_t gUnframedSamples;
static uint32_t gEmulatedWriteCount;
static uint32_t gEmulatedCompleteCount;
static NFCFBoundedAppendLog gLog = NFCF_BOUNDED_APPEND_LOG_INITIALIZER(
    nfcf_backend::kObserverResultPath);

typedef struct {
    int active;
    uint8_t header[3];
    uint32_t sequence;
} PendingNciFrame;

static PendingNciFrame gPendingFrame;
static pthread_mutex_t gPendingMutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    uint8_t packet[128];
    uint16_t length;
    uint8_t command;
    uint8_t felica_length;
} EmulatedResponse;

static void append_line(const char *format, ...) {
    char buffer[1024];
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

static void write_ready(void) {
    char output[64] = {};
    int length = snprintf(output, sizeof(output), "observer=installed pid=%d\n",
                          getpid());
    if (length <= 0 || (size_t)length >= sizeof(output)) return;
    (void)nfcf_backend::WriteSecureTextFile(
        nfcf_backend::kObserverReadyPath, output);
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

static int contains_bytes(const uint8_t *haystack, size_t haystack_length,
                          const uint8_t *needle, size_t needle_length) {
    if (haystack == NULL || needle == NULL || needle_length == 0 ||
        haystack_length < needle_length) return 0;
    for (size_t index = 0; index <= haystack_length - needle_length;
         ++index) {
        if (memcmp(haystack + index, needle, needle_length) == 0) return 1;
    }
    return 0;
}

static int contains_active_idm(const uint8_t *bytes, size_t length) {
    nfcf::Profile profile = {};
    return nfcf::CopyActiveProfile(&profile) &&
           contains_bytes(bytes, length, profile.idm, sizeof(profile.idm));
}

static uint16_t transport_crc16(const uint8_t *bytes, size_t length) {
    uint16_t crc = 0xffff;
    for (size_t index = 0; index < length; ++index) {
        crc ^= (uint16_t)bytes[index] << 8;
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x8000)
                ? (uint16_t)((crc << 1) ^ 0x1021)
                : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static void emulated_write_complete(void *opaque,
                                     TmlTransactionInfo *information) {
    EmulatedResponse *response = (EmulatedResponse *)opaque;
    uint8_t status = information == NULL ? 0xff : information->status & 0xff;
    if (status == 0)
        gLastResponseAt.store(time(NULL), std::memory_order_relaxed);
    uint32_t count = __sync_add_and_fetch(&gEmulatedCompleteCount, 1);
    if (status != 0 || count <= 4 || count % 100 == 0) {
        append_line("event=nci-emulated-response-complete count=%u "
                    "command=0x%02X status=0x%02X length=%u", count,
                    response == NULL ? 0xff : response->command, status,
                    response == NULL ? 0 : response->length);
    }
    free(response);
}

static void maybe_send_emulated_response(
    void *tml_context, const uint8_t header[3], const uint8_t *payload,
    size_t payload_length) {
    if (gEmulatedWrite == NULL || tml_context == NULL || header == NULL ||
        payload == NULL || ((header[0] >> 5) & 0x7) != 0 ||
        payload_length < 3 || payload[payload_length - 1] != 0x00)
        return;

    uint8_t felica_response[96] = {};
    const nfcf::DispatchResult dispatch =
        nfcf::Dispatch(payload, payload_length - 1,
                                 felica_response,
                                 sizeof(felica_response));
    if (dispatch.status != nfcf::DispatchStatus::kResponse)
        return;

    EmulatedResponse *response =
        (EmulatedResponse *)malloc(sizeof(EmulatedResponse));
    if (response == NULL) {
        append_line("event=nci-emulated-response allocation=failed");
        return;
    }

    uint8_t *packet = response->packet;
    const uint8_t payload_size =
        (uint8_t)dispatch.response_length;
    packet[0] = header[0] & 0x0f;
    packet[1] = 0;
    packet[2] = payload_size;
    memcpy(packet + 3, felica_response, payload_size);
    size_t nci_length = 3 + payload_size;
    uint16_t crc = transport_crc16(packet, nci_length);
    packet[nci_length] = (uint8_t)(crc >> 8);
    packet[nci_length + 1] = (uint8_t)crc;
    response->length = (uint16_t)(nci_length + 2);
    response->command = dispatch.request_command;
    response->felica_length = payload_size;

    uint32_t result = gEmulatedWrite(
        tml_context, packet, response->length,
        emulated_write_complete, response);
    uint32_t count = __sync_add_and_fetch(&gEmulatedWriteCount, 1);
    if ((result & 0xff) != 0x0d || count <= 4 || count % 100 == 0) {
        append_line("event=nci-emulated-response count=%u command=0x%02X "
                    "felicaLength=%u transportLength=%u status=0x%02X",
                    count, response->command, response->felica_length,
                    response->length, result & 0xff);
    }
    if ((result & 0xff) != 0x0d) {
        free(response);
    } else if (dispatch.request_command == 0x06) {
        (void)notify_post(kTransmitNotification);
    }
}

static const char *notification_name(uint8_t gid, uint8_t oid) {
    if (gid == 0 && oid == 7) return "CORE_GENERIC_ERROR";
    if (gid != 1) return "OTHER";
    switch (oid) {
        case 3: return "RF_DISCOVER";
        case 5: return "RF_INTF_ACTIVATED";
        case 6: return "RF_DEACTIVATE";
        case 7: return "RF_FIELD";
        case 8: return "RF_T3T_POLLING";
        default: return "RF_OTHER";
    }
}

static const char *response_name(uint8_t gid, uint8_t oid) {
    if (gid == 0 && oid == 2) return "CORE_SET_CONFIG";
    if (gid == 0 && oid == 3) return "CORE_GET_CONFIG";
    if (gid != 1) return NULL;
    switch (oid) {
        case 0: return "RF_DISCOVER_MAP";
        case 1: return "RF_SET_LISTEN_MODE_ROUTING";
        case 3: return "RF_DISCOVER";
        default: return NULL;
    }
}

static void log_core_get_config_response(uint32_t sequence,
                                         const uint8_t *payload,
                                         size_t payload_length) {
    if (payload == NULL || payload_length < 2) {
        append_line("event=nci-frame seq=%u mt=response "
                    "name=CORE_GET_CONFIG malformed=yes", sequence);
        return;
    }
    uint8_t status = payload[0];
    uint8_t count = payload[1];
    append_line("event=nci-frame seq=%u mt=response name=CORE_GET_CONFIG "
                "status=0x%02X params=%u payloadLen=%zu", sequence,
                status, count, payload_length);
    size_t cursor = 2;
    for (uint8_t index = 0; index < count; ++index) {
        if (cursor + 2 > payload_length) return;
        uint16_t identifier = payload[cursor++];
        if (identifier == 0xa0) {
            if (cursor + 2 > payload_length) return;
            identifier = (uint16_t)(0xa000 | payload[cursor++]);
        }
        uint8_t value_length = payload[cursor++];
        if (cursor + value_length > payload_length) return;
        if (identifier == 0x52 && value_length == 1) {
            append_line("event=nci-get-param-response seq=%u id=0x0052 "
                        "value=%u", sequence, payload[cursor]);
        }
        cursor += value_length;
    }
}

static void log_complete_frame(uint32_t sequence, const uint8_t header[3],
                               const uint8_t *payload,
                               size_t payload_length,
                               size_t reported_length) {
    uint8_t message_type = (header[0] >> 5) & 0x7;
    if (message_type == 0) {
        int emulated = contains_active_idm(payload, payload_length);
        if (emulated) {
            append_line("event=nci-frame seq=%u mt=data connId=%u "
                        "payloadLen=%zu emulated=yes redacted=yes", sequence,
                        header[0] & 0x0f, payload_length);
        }
        return;
    }
    uint8_t gid = header[0] & 0x0f;
    uint8_t oid = header[1] & 0x3f;
    if (message_type == 2) {
        const char *name = response_name(gid, oid);
        if (gid == 0 && oid == 3) {
            log_core_get_config_response(sequence, payload, payload_length);
            return;
        }
        if (name != NULL) {
            append_line("event=nci-frame seq=%u mt=response name=%s "
                        "status=0x%02X payloadLen=%zu", sequence, name,
                        payload_length == 0 ? 0xff : payload[0],
                        payload_length);
        }
        return;
    }
    if (message_type != 3) return;

    const char *name = notification_name(gid, oid);
    if (gid == 0 && oid == 7) {
        append_line("event=nci-frame seq=%u mt=notification name=%s "
                    "status=0x%02X payloadLen=%zu", sequence, name,
                    payload_length == 0 ? 0xff : payload[0],
                    payload_length);
        return;
    }
    if (gid != 1) return;

    switch (oid) {
        case 3:
            append_line("event=nci-frame seq=%u mt=notification name=%s "
                        "discoveryId=0x%02X protocol=0x%02X mode=0x%02X "
                        "payloadLen=%zu", sequence, name,
                        payload_length >= 1 ? payload[0] : 0xff,
                        payload_length >= 2 ? payload[1] : 0xff,
                        payload_length >= 3 ? payload[2] : 0xff,
                        payload_length);
            break;
        case 5:
            gActivationGeneration.fetch_add(1, std::memory_order_relaxed);
            gLastActivationAt.store(time(NULL), std::memory_order_relaxed);
            append_line("event=nci-frame seq=%u mt=notification name=%s "
                        "interface=0x%02X protocol=0x%02X mode=0x%02X "
                        "emulated=%s payloadLen=%zu", sequence, name,
                        payload_length >= 2 ? payload[1] : 0xff,
                        payload_length >= 3 ? payload[2] : 0xff,
                        payload_length >= 4 ? payload[3] : 0xff,
                        contains_active_idm(payload, payload_length)
                            ? "yes" : "no",
                        payload_length);
            break;
        case 6:
            append_line("event=nci-frame seq=%u mt=notification name=%s "
                        "type=0x%02X payloadLen=%zu", sequence, name,
                        payload_length == 0 ? 0xff : payload[0],
                        payload_length);
            break;
        case 7: {
            int field_on = payload_length != 0 && payload[0] != 0;
            uint32_t count = field_on
                ? __sync_add_and_fetch(&gFieldOnCount, 1)
                : __sync_add_and_fetch(&gFieldOffCount, 1);
            if (count == 1 || count % 100 == 0) {
                append_line("event=nci-frame seq=%u mt=notification name=%s "
                            "field=%s count=%u payloadLen=%zu reported=%zu",
                            sequence, name, field_on ? "on" : "off", count,
                            payload_length, reported_length);
            }
            if (field_on) {
                gLastFieldAt.store(time(NULL), std::memory_order_relaxed);
                gRecoverGeneration.store(
                    gActivationGeneration.load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
                if (gRecoverTimer != NULL) {
                    dispatch_source_set_timer(
                        gRecoverTimer,
                        dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC),
                        DISPATCH_TIME_FOREVER, 50 * NSEC_PER_MSEC);
                }
            }
            break;
        }
        case 8:
            append_line("event=nci-frame seq=%u mt=notification name=%s "
                        "status=0x%02X responses=%u payloadLen=%zu",
                        sequence, name,
                        payload_length >= 1 ? payload[0] : 0xff,
                        payload_length >= 2 ? payload[1] : 0,
                        payload_length);
            break;
        default:
            break;
    }
}

static void log_incoming(void *tml_context, TmlTransactionInfo *information,
                         const uint8_t *request_buffer,
                         size_t request_length) {
    if (information == NULL) {
        append_line("event=nci-read info=null");
        pthread_mutex_lock(&gPendingMutex);
        gPendingFrame.active = 0;
        pthread_mutex_unlock(&gPendingMutex);
        return;
    }
    const uint8_t *buffer = information->buffer;
    size_t reported_length = information->length;
    if (information->status != 0 || buffer == NULL ||
        reported_length > 4096) {
        append_line("event=nci-read status=0x%02X reported=%zu "
                    "packet=unavailable", information->status & 0xff,
                    reported_length);
        pthread_mutex_lock(&gPendingMutex);
        gPendingFrame.active = 0;
        pthread_mutex_unlock(&gPendingMutex);
        return;
    }

    PendingNciFrame pending = {};
    pthread_mutex_lock(&gPendingMutex);
    if (gPendingFrame.active) {
        pending = gPendingFrame;
        gPendingFrame.active = 0;
    }
    pthread_mutex_unlock(&gPendingMutex);
    if (pending.active) {
        uint8_t expected = pending.header[2];
        if (reported_length < expected) {
            append_line("event=nci-frame seq=%u expected=%u reported=%zu "
                        "truncated=yes", pending.sequence, expected,
                        reported_length);
            return;
        }
        maybe_send_emulated_response(
            tml_context, pending.header, buffer, expected);
        log_complete_frame(pending.sequence, pending.header,
                           buffer, expected, reported_length);
        return;
    }

    if (reported_length != 3) {
        uint32_t sample = __sync_add_and_fetch(&gUnframedSamples, 1);
        if (sample <= 4) {
            append_line("event=nci-read unframed=yes reported=%zu "
                        "requested=%zu sameBuffer=%s", reported_length,
                        request_length,
                        buffer == request_buffer ? "yes" : "no");
        }
        return;
    }
    uint8_t message_type = (buffer[0] >> 5) & 0x7;
    if (message_type != 0 && message_type != 2 && message_type != 3) {
        uint32_t sample = __sync_add_and_fetch(&gUnframedSamples, 1);
        if (sample <= 4) {
            append_line("event=nci-read unframed=yes header=%02X%02X%02X",
                        buffer[0], buffer[1], buffer[2]);
        }
        return;
    }
    PendingNciFrame next = {};
    next.sequence = __sync_add_and_fetch(&gSequence, 1);
    memcpy(next.header, buffer, sizeof(next.header));
    next.active = 1;
    if (buffer[2] == 0) {
        next.active = 0;
        log_complete_frame(next.sequence, next.header, NULL, 0, 0);
        return;
    }
    pthread_mutex_lock(&gPendingMutex);
    gPendingFrame = next;
    pthread_mutex_unlock(&gPendingMutex);
}

static void observed_read_callback(void *opaque,
                                   TmlTransactionInfo *information) {
    ObservedReadCallback *observed = (ObservedReadCallback *)opaque;
    if (observed == NULL) return;
    log_incoming(observed->tml_context, information,
                 observed->request_buffer,
                 observed->request_length);
    TmlReadCallback callback = observed->callback;
    void *user_context = observed->user_context;
    free(observed);
    if (callback != NULL) callback(user_context, information);
}

static uint32_t observed_tml_read(void *tml_context, uint8_t *buffer,
                                  uint16_t length, TmlReadCallback callback,
                                  void *user_context) {
    ObservedReadCallback *observed =
        (ObservedReadCallback *)malloc(sizeof(ObservedReadCallback));
    if (observed == NULL)
        return gOriginalRead(tml_context, buffer, length, callback,
                             user_context);
    observed->callback = callback;
    observed->user_context = user_context;
    observed->tml_context = tml_context;
    observed->request_buffer = buffer;
    observed->request_length = length;
    uint32_t result = gOriginalRead(tml_context, buffer, length,
                                    observed_read_callback, observed);
    if ((result & 0xff) != 0x0d) free(observed);
    return result;
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
    kern_return_t write_result = vm_protect(
        mach_task_self(), page, page_size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (write_result != KERN_SUCCESS) return -(100 + write_result);
    memcpy(address, &replacement, sizeof(replacement));
    sys_icache_invalidate(address, sizeof(replacement));
    kern_return_t restore_result = vm_protect(
        mach_task_self(), page, page_size, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    if (restore_result != KERN_SUCCESS) return -(200 + restore_result);
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
    kern_return_t write_result = vm_protect(
        mach_task_self(), page, page_size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (write_result != KERN_SUCCESS) return -(100 + write_result);
    memcpy(slot, &replacement, sizeof(replacement));
    kern_return_t restore_result = vm_protect(
        mach_task_self(), page, page_size, FALSE, VM_PROT_READ);
    if (restore_result != KERN_SUCCESS) return -(200 + restore_result);
    memcpy(&current, slot, sizeof(current));
    return current == replacement ? 0 : -3;
}

extern "C" void NFCFInitializeNCIReadObserver(void) {
    NFCFResetBoundedAppendLog(&gLog);

    void *route_symbol = dlsym(RTLD_DEFAULT,
                               "phLibNfc_Mgt_ConfigRoutingTable");
    Dl_info nfc_info = {};
    if (route_symbol == NULL || dladdr(route_symbol, &nfc_info) == 0 ||
        nfc_info.dli_fbase == NULL ||
        (uintptr_t)route_symbol - (uintptr_t)nfc_info.dli_fbase !=
            nfcf_backend::nfc_offsets::kLibNFCConfigRouting ||
        !nfcf_backend::MatchesReadableMemory(
            route_symbol, kExpectedLibNFCPrologue,
            sizeof(kExpectedLibNFCPrologue))) {
        append_line("observer=refused reason=libnfc-image-mismatch");
        return;
    }

    void *tml_read = dlsym(RTLD_DEFAULT, "phTmlNfc_Read");
    Dl_info read_info = {};
    if (tml_read == NULL || dladdr(tml_read, &read_info) == 0 ||
        read_info.dli_fbase == NULL ||
        (uintptr_t)tml_read - (uintptr_t)read_info.dli_fbase !=
            nfcf_backend::nfc_offsets::kTmlReadExport ||
        !nfcf_backend::MatchesReadableMemory(
            tml_read, kExpectedTmlReadPrologue,
            sizeof(kExpectedTmlReadPrologue))) {
        append_line("observer=refused reason=tml-read-export-mismatch");
        return;
    }

    void *tml_write = dlsym(RTLD_DEFAULT, "phTmlNfc_Write");
    Dl_info write_info = {};
    if (tml_write == NULL || dladdr(tml_write, &write_info) == 0 ||
        write_info.dli_fbase == NULL ||
        write_info.dli_fbase != read_info.dli_fbase ||
        (uintptr_t)tml_write - (uintptr_t)write_info.dli_fbase !=
            nfcf_backend::nfc_offsets::kTmlWriteExport ||
        !nfcf_backend::MatchesReadableMemory(
            tml_write, kExpectedTmlWritePrologue,
            sizeof(kExpectedTmlWritePrologue))) {
        append_line("observer=refused reason=tml-write-export-mismatch");
        return;
    }

    uint8_t *nfc_base = (uint8_t *)nfc_info.dli_fbase;
    uint8_t *common_island = NULL;
    for (size_t index = 0;
         index < sizeof(kReadCallsites) / sizeof(kReadCallsites[0]);
        ++index) {
        uint8_t *callsite = nfc_base + kReadCallsites[index].offset;
        if (!nfcf_backend::MatchesReadableMemory(
                callsite, kReadCallsites[index].expected,
                sizeof(kReadCallsites[index].expected))) {
            append_line("observer=refused reason=read-callsite-%zu-mismatch",
                        index);
            return;
        }
        uint8_t *target = decode_bl_target(callsite);
        if (common_island == NULL) common_island = target;
        if (target != common_island) {
            append_line("observer=refused reason=read-target-%zu-mismatch",
                        index);
            return;
        }
    }
    if (common_island == NULL ||
        !nfcf_backend::MatchesReadableMemory(
            common_island, kExpectedTmlReadIsland,
            sizeof(kExpectedTmlReadIsland)) ||
        decode_adrp_add_target(common_island) != tml_read) {
        append_line("observer=refused reason=read-island-mismatch");
        return;
    }

    uint8_t *local_stub =
        nfc_base + nfcf_backend::nfc_offsets::kTmlReadLocalStub;
    if (!nfcf_backend::MatchesReadableMemory(
            local_stub, kExpectedTmlReadLocalStub,
            sizeof(kExpectedTmlReadLocalStub))) {
        append_line("observer=refused reason=read-local-stub-mismatch");
        return;
    }
    void **read_slot = decode_adrp_ldr_slot(local_stub);
    if (!nfcf_backend::IsReadableMemory(read_slot, sizeof(*read_slot))) {
        append_line("observer=refused reason=read-binding-unreadable");
        return;
    }
    void *bound_target = NULL;
    memcpy(&bound_target, read_slot, sizeof(bound_target));
    if (bound_target != tml_read) {
        append_line("observer=refused reason=read-binding-mismatch");
        return;
    }

    gOriginalRead = (TmlReadFn)tml_read;
    gEmulatedWrite = (TmlWriteFn)tml_write;
    size_t patched = 0;
    int result = 0;
    for (; patched < sizeof(kReadCallsites) / sizeof(kReadCallsites[0]);
         ++patched) {
        uint8_t *callsite = nfc_base + kReadCallsites[patched].offset;
        uint32_t original = 0;
        uint32_t replacement = 0;
        memcpy(&original, kReadCallsites[patched].expected,
               sizeof(original));
        result = encode_bl(callsite, local_stub, &replacement);
        if (result == 0)
            result = replace_code_word(callsite, original, replacement);
        if (result != 0) break;
    }
    if (result == 0)
        result = replace_pointer(read_slot, tml_read,
                                 (void *)observed_tml_read);
    if (result != 0) {
        while (patched > 0) {
            --patched;
            uint8_t *callsite = nfc_base + kReadCallsites[patched].offset;
            uint32_t original = 0;
            uint32_t replacement = 0;
            memcpy(&original, kReadCallsites[patched].expected,
                   sizeof(original));
            if (encode_bl(callsite, local_stub, &replacement) == 0)
                (void)replace_code_word(callsite, replacement, original);
        }
        gOriginalRead = NULL;
        gEmulatedWrite = NULL;
        append_line("observer=failed reason=read-local-route-patch code=%d",
                    result);
        return;
    }

    gRecoverTimer = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    if (gRecoverTimer != NULL) {
        dispatch_source_set_event_handler(gRecoverTimer, ^{
            time_t now = time(NULL);
            time_t previous =
                gLastRecoverPost.load(std::memory_order_relaxed);
            if (gActivationGeneration.load(std::memory_order_relaxed) ==
                    gRecoverGeneration.load(std::memory_order_relaxed) &&
                now - previous >= 5 &&
                gLastRecoverPost.compare_exchange_strong(
                    previous, now, std::memory_order_relaxed)) {
                append_line("event=nci-auto-recover reason=field-without-activation");
                NFCFRecoverRouteInternally();
            }
        });
        dispatch_activate(gRecoverTimer);
    } else {
        append_line("observer=warning reason=recover-timer-unavailable");
    }

    append_line("observer=installed method=guarded-local-stub "
                "callsites=%zu stub=0x%lx export=0x%lx "
                "emulatedResponder=yes writeExport=0x%lx pid=%d",
                sizeof(kReadCallsites) / sizeof(kReadCallsites[0]),
                (unsigned long)nfcf_backend::nfc_offsets::kTmlReadLocalStub,
                (unsigned long)nfcf_backend::nfc_offsets::kTmlReadExport,
                (unsigned long)nfcf_backend::nfc_offsets::kTmlWriteExport,
                getpid());
    write_ready();
}
