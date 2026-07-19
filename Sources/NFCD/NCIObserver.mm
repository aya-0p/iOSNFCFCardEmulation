#include <dlfcn.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <atomic>

#include "NFCFProtocol.hpp"
#include "BoundedAppendLog.hpp"
#include "Core/BackendPaths.hpp"
#include "Core/ReadableMemory.hpp"
#include "Platform/NFCOffsets.hpp"

static const uint8_t kExpectedLibNFCPrologue[8] = {
    0xff, 0x83, 0x01, 0xd1, 0xf8, 0x5f, 0x02, 0xa9
};
static const uint8_t kExpectedTmlWritePrologue[8] = {
    0xff, 0x43, 0x03, 0xd1, 0xf8, 0x5f, 0x09, 0xa9
};
static const uint8_t kExpectedTmlWriteLocalStub[12] = {
    0xb0, 0x34, 0x0c, 0x90, 0x10, 0xfa,
    0x46, 0xf9, 0x00, 0x02, 0x1f, 0xd6
};
static const uint8_t kExpectedTmlWriteIsland[12] = {
    0x10, 0xa5, 0xfe, 0xd0, 0x10, 0x82,
    0x0f, 0x91, 0x00, 0x02, 0x1f, 0xd6
};

typedef struct {
    uintptr_t offset;
    uint8_t expected[4];
} WriteCallsite;

static const WriteCallsite kWriteCallsites[] = {
    {0x03f28, {0x50, 0x81, 0xde, 0x94}},
    {0x04068, {0x00, 0x81, 0xde, 0x94}},
    {0x0416c, {0xbf, 0x80, 0xde, 0x94}},
    {0x10084, {0xf9, 0x50, 0xde, 0x94}},
    {0x401ac, {0xaf, 0x90, 0xdd, 0x94}},
    {0x40718, {0x54, 0x8f, 0xdd, 0x94}},
    {0x6aa3c, {0x8b, 0xe6, 0xdc, 0x94}},
    {0x6ac0c, {0x17, 0xe6, 0xdc, 0x94}},
};
typedef uint32_t (*TmlWriteFn)(void *tml_context, const uint8_t *buffer,
                               uint16_t length, void *callback,
                               void *user_context);

static TmlWriteFn gOriginalWrite;
static uint32_t gSequence;
static std::atomic<int> gEmulatedSession{0};
static NFCFBoundedAppendLog gLog = NFCF_BOUNDED_APPEND_LOG_INITIALIZER(
    nfcf_backend::kNCIObserverResultPath);

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

static int profile_is_active(void) {
    nfcf::Profile profile = {};
    return nfcf::CopyActiveProfile(&profile);
}

static void log_core_set_config(uint32_t sequence, const uint8_t *payload,
                                size_t length) {
    if (length == 0) {
        append_line("event=nci-core-set-config seq=%u malformed=yes",
                    sequence);
        return;
    }
    uint8_t count = payload[0];
    int emulated_context = contains_active_idm(payload, length);
    append_line("event=nci-core-set-config seq=%u params=%u payloadLen=%zu",
                sequence, count, length);
    size_t cursor = 1;
    for (uint8_t index = 0; index < count; ++index) {
        if (cursor + 2 > length) {
            append_line("event=nci-param seq=%u index=%u malformed=yes",
                        sequence, index);
            return;
        }
        uint16_t identifier = payload[cursor++];
        if (identifier == 0xa0) {
            if (cursor + 2 > length) {
                append_line("event=nci-param seq=%u index=%u "
                            "vendor=yes malformed=yes", sequence, index);
                return;
            }
            identifier = (uint16_t)(0xa000 | payload[cursor++]);
        }
        uint8_t value_length = payload[cursor++];
        if (cursor + value_length > length) {
            append_line("event=nci-param seq=%u index=%u id=0x%02X "
                        "len=%u malformed=yes", sequence, index,
                        identifier, value_length);
            return;
        }
        const uint8_t *value = payload + cursor;
        int is_t3t_identifier = identifier >= 0x40 && identifier <= 0x4f;
        int is_emulated = is_t3t_identifier &&
            contains_active_idm(value, value_length);
        if (is_emulated) {
            append_line("event=nci-param seq=%u index=%u id=0x%04X "
                        "len=%u t3t=yes emulated=yes redacted=yes",
                        sequence, index, identifier, value_length);
        } else if (is_t3t_identifier) {
            // Never emit identifiers belonging to unrelated system routes.
            append_line("event=nci-param seq=%u index=%u id=0x%04X "
                        "len=%u t3t=yes emulated=no", sequence, index,
                        identifier, value_length);
        } else if ((emulated_context ||
                    gEmulatedSession.load(std::memory_order_relaxed) != 0) &&
                   (identifier == 0x00 || identifier == 0x32 ||
                    identifier == 0x50 || identifier == 0x51 ||
                    identifier == 0x52 || identifier == 0x53 ||
                    identifier == 0x54 || identifier == 0x55 ||
                    identifier == 0xa040 || identifier == 0xa08f ||
                    identifier == 0xa0fa)) {
            append_line("event=nci-param seq=%u index=%u id=0x%04X "
                        "len=%u emulated-session=yes redacted=yes",
                        sequence, index, identifier, value_length);
        } else {
            append_line("event=nci-param seq=%u index=%u id=0x%04X len=%u",
                        sequence, index, identifier, value_length);
        }
        cursor += value_length;
    }
}

static void log_core_get_config(uint32_t sequence, const uint8_t *payload,
                                size_t length) {
    if (payload == NULL || length == 0) {
        append_line("event=nci-core-get-config seq=%u malformed=yes",
                    sequence);
        return;
    }
    uint8_t count = payload[0];
    append_line("event=nci-core-get-config seq=%u params=%u payloadLen=%zu",
                sequence, count, length);
    size_t cursor = 1;
    for (uint8_t index = 0; index < count; ++index) {
        if (cursor >= length) {
            append_line("event=nci-get-param seq=%u index=%u malformed=yes",
                        sequence, index);
            return;
        }
        uint16_t identifier = payload[cursor++];
        if (identifier == 0xa0) {
            if (cursor >= length) {
                append_line("event=nci-get-param seq=%u index=%u "
                            "vendor=yes malformed=yes", sequence, index);
                return;
            }
            identifier = (uint16_t)(0xa000 | payload[cursor++]);
        }
        append_line("event=nci-get-param seq=%u index=%u id=0x%04X",
                    sequence, index, identifier);
    }
}

static void log_listen_mode_routing(uint32_t sequence,
                                    const uint8_t *payload,
                                    size_t length) {
    // NCI RF_SET_LISTEN_MODE_ROUTING starts with More and Num Entries.
    // Only technology/protocol routes are generic enough to emit. AID and
    // unknown route payloads remain redacted.
    if (payload == NULL || length < 2) {
        append_line("event=nci-routing seq=%u malformed=yes payloadLen=%zu",
                    sequence, length);
        return;
    }
    uint8_t more = payload[0];
    uint8_t count = payload[1];
    append_line("event=nci-routing seq=%u more=%u entries=%u payloadLen=%zu",
                sequence, more, count, length);
    size_t cursor = 2;
    for (uint8_t index = 0; index < count; ++index) {
        if (cursor + 2 > length) {
            append_line("event=nci-route-entry seq=%u index=%u "
                        "malformed=yes", sequence, index);
            return;
        }
        uint8_t type = payload[cursor++];
        uint8_t entry_length = payload[cursor++];
        if (cursor + entry_length > length) {
            append_line("event=nci-route-entry seq=%u index=%u type=%u "
                        "len=%u malformed=yes", sequence, index, type,
                        entry_length);
            return;
        }
        if ((type == 0 || type == 1) && entry_length == 3) {
            append_line("event=nci-route-entry seq=%u index=%u kind=%s "
                        "destination=0x%02X power=0x%02X value=0x%02X",
                        sequence, index,
                        type == 0 ? "technology" : "protocol",
                        payload[cursor], payload[cursor + 1],
                        payload[cursor + 2]);
        } else {
            append_line("event=nci-route-entry seq=%u index=%u type=%u "
                        "len=%u redacted=yes", sequence, index, type,
                        entry_length);
        }
        cursor += entry_length;
    }
    if (cursor != length) {
        append_line("event=nci-routing seq=%u trailing=%zu redacted=yes",
                    sequence, length - cursor);
    }
}

static const char *relevant_command(const uint8_t *buffer, size_t length) {
    if (buffer == NULL || length < 3 || (buffer[0] & 0xe0) != 0x20)
        return NULL;
    uint8_t gid = buffer[0] & 0x0f;
    uint8_t oid = buffer[1] & 0x3f;
    if (gid == 0 && oid == 2) return "CORE_SET_CONFIG";
    if (gid == 0 && oid == 3) return "CORE_GET_CONFIG";
    if (gid == 1 && oid == 0) return "RF_DISCOVER_MAP";
    if (gid == 1 && oid == 1) return "RF_SET_LISTEN_MODE_ROUTING";
    if (gid == 1 && oid == 3) return "RF_DISCOVER";
    return NULL;
}

static void log_command(uint32_t sequence, const char *name,
                        const uint8_t *buffer, size_t length) {
    size_t payload_length = length >= 3 ? buffer[2] : 0;
    if (payload_length > length - 3) payload_length = length - 3;
    const uint8_t *payload = buffer + 3;
    append_line("event=nci-write seq=%u command=%s length=%zu",
                sequence, name, length);
    if (strcmp(name, "CORE_SET_CONFIG") == 0) {
        log_core_set_config(sequence, payload, payload_length);
        return;
    }
    if (strcmp(name, "CORE_GET_CONFIG") == 0) {
        log_core_get_config(sequence, payload, payload_length);
        return;
    }
    if (strcmp(name, "RF_SET_LISTEN_MODE_ROUTING") == 0) {
        log_listen_mode_routing(sequence, payload, payload_length);
        return;
    }
    append_line("event=nci-payload seq=%u payloadLen=%zu redacted=yes",
                sequence, payload_length);
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

static unsigned rewrite_emulated_t3t_system_code(uint8_t *buffer,
                                                   uint16_t *length,
                                                   uint16_t *system_code) {
    if (buffer == NULL || length == NULL || *length < 4 ||
        (buffer[0] & 0xe0) != 0x20 ||
        (buffer[0] & 0x0f) != 0 || (buffer[1] & 0x3f) != 2)
        return 0;
    size_t payload_length = buffer[2];
    size_t frame_length = 3 + payload_length;
    if (payload_length < 1 || frame_length + 2 != *length) return 0;
    uint16_t original_crc = transport_crc16(buffer, frame_length);
    if (buffer[frame_length] != (uint8_t)(original_crc >> 8) ||
        buffer[frame_length + 1] != (uint8_t)original_crc)
        return 0;

    nfcf::Profile active_profile = {};
    if (!nfcf::CopyActiveProfile(&active_profile)) return 0;

    uint8_t *payload = buffer + 3;
    uint8_t count = payload[0];
    size_t cursor = 1;
    uint8_t *candidates[16] = {};
    unsigned candidate_count = 0;
    uint8_t *flags2 = NULL;
    for (uint8_t index = 0; index < count; ++index) {
        if (cursor + 2 > payload_length) return 0;
        uint16_t identifier = payload[cursor++];
        if (identifier == 0xa0) {
            if (cursor + 2 > payload_length) return 0;
            identifier = (uint16_t)(0xa000 | payload[cursor++]);
        }
        uint8_t value_length = payload[cursor++];
        if (cursor + value_length > payload_length) return 0;
        uint8_t *value = payload + cursor;
        if (identifier == 0x53 && value_length == 2 &&
            value[0] == 0x00 && value[1] == 0x0f)
            flags2 = value;
        if (identifier >= 0x40 && identifier <= 0x4f &&
            value_length == 10 && value[0] == 0xff && value[1] == 0xff &&
            memcmp(value + 2, active_profile.idm,
                   sizeof(active_profile.idm)) == 0) {
            if (candidate_count >=
                sizeof(candidates) / sizeof(candidates[0])) return 0;
            if (identifier != (uint16_t)(0x40 + candidate_count)) return 0;
            candidates[candidate_count++] = value;
        }
        cursor += value_length;
    }
    if (count != 7 || cursor != payload_length || candidate_count != 4 ||
        flags2 == NULL)
        return 0;

    candidates[0][0] = static_cast<uint8_t>(active_profile.system_code >> 8);
    candidates[0][1] = static_cast<uint8_t>(active_profile.system_code & 0xff);
    // Standard NCI octet order: bit 0 of the first octet enables ID1.
    flags2[0] = 0x01;
    flags2[1] = 0x00;
    payload[0] = 4;  // bitrate, PMm, flags, and one T3T identifier
    size_t updated_payload_length =
        (size_t)(candidates[0] + 10 - payload);
    buffer[2] = (uint8_t)updated_payload_length;
    size_t updated_frame_length = 3 + updated_payload_length;
    uint16_t updated_crc = transport_crc16(buffer, updated_frame_length);
    buffer[updated_frame_length] = (uint8_t)(updated_crc >> 8);
    buffer[updated_frame_length + 1] = (uint8_t)updated_crc;
    *length = (uint16_t)(updated_frame_length + 2);
    if (system_code != NULL) *system_code = active_profile.system_code;
    return 1;
}

static unsigned rewrite_emulated_t3t_discover_map(uint8_t *buffer,
                                                    size_t length) {
    // Apple's stock map contains ISO-DEP plus its proprietary poll-only
    // interface. For the emulated Type-F session, replace only the exact
    // proprietary mapping with the NCI T3T/listen/frame mapping. Keeping the
    // packet size unchanged avoids changing ownership/lifetime of TML data.
    if (gEmulatedSession.load(std::memory_order_relaxed) == 0 ||
        !profile_is_active() ||
        buffer == NULL || length < 4 ||
        (buffer[0] & 0xe0) != 0x20 || (buffer[0] & 0x0f) != 1 ||
        (buffer[1] & 0x3f) != 0)
        return 0;
    size_t payload_length = buffer[2];
    size_t frame_length = 3 + payload_length;
    if (payload_length < 4 || frame_length + 2 > length)
        return 0;
    uint16_t original_crc = transport_crc16(buffer, frame_length);
    if (buffer[frame_length] != (uint8_t)(original_crc >> 8) ||
        buffer[frame_length + 1] != (uint8_t)original_crc)
        return 0;

    uint8_t *payload = buffer + 3;
    uint8_t count = payload[0];
    if ((size_t)count * 3 + 1 != payload_length) return 0;
    int has_iso_dep = 0;
    uint8_t *proprietary = NULL;
    for (uint8_t index = 0; index < count; ++index) {
        uint8_t *mapping = payload + 1 + (size_t)index * 3;
        if (mapping[0] == 0x04 && mapping[1] == 0x03 &&
            mapping[2] == 0x02)
            has_iso_dep = 1;
        if (mapping[0] == 0x80 && mapping[1] == 0x01 &&
            mapping[2] == 0x80) {
            if (proprietary != NULL) return 0;
            proprietary = mapping;
        }
    }
    if (!has_iso_dep || proprietary == NULL) return 0;
    proprietary[0] = 0x03;  // NCI_PROTOCOL_T3T
    proprietary[1] = 0x02;  // NCI_INTERFACE_MODE_LISTEN
    proprietary[2] = 0x01;  // NCI_INTERFACE_FRAME
    uint16_t updated_crc = transport_crc16(buffer, frame_length);
    buffer[frame_length] = (uint8_t)(updated_crc >> 8);
    buffer[frame_length + 1] = (uint8_t)updated_crc;
    return 1;
}

static unsigned rewrite_emulated_type_f_route_to_host(uint8_t *buffer,
                                                       size_t length) {
    if (gEmulatedSession.load(std::memory_order_relaxed) == 0 ||
        !profile_is_active() ||
        buffer == NULL || length < 4 ||
        (buffer[0] & 0xe0) != 0x20 || (buffer[0] & 0x0f) != 1 ||
        (buffer[1] & 0x3f) != 1)
        return 0;
    size_t payload_length = buffer[2];
    size_t frame_length = 3 + payload_length;
    if (payload_length < 2 || frame_length + 2 > length)
        return 0;
    uint16_t original_crc = transport_crc16(buffer, frame_length);
    if (buffer[frame_length] != (uint8_t)(original_crc >> 8) ||
        buffer[frame_length + 1] != (uint8_t)original_crc)
        return 0;

    uint8_t *payload = buffer + 3;
    uint8_t count = payload[1];
    size_t cursor = 2;
    uint8_t *type_f_route = NULL;
    int has_t3t_host_route = 0;
    for (uint8_t index = 0; index < count; ++index) {
        if (cursor + 2 > payload_length) return 0;
        uint8_t type = payload[cursor++];
        uint8_t entry_length = payload[cursor++];
        if (cursor + entry_length > payload_length) return 0;
        uint8_t *entry = payload + cursor;
        if (type == 1 && entry_length == 3 && entry[0] == 0x00 &&
            entry[1] == 0x01 && entry[2] == 0x03)
            has_t3t_host_route = 1;
        if (type == 0 && entry_length == 3 && entry[0] == 0xc0 &&
            entry[1] == 0x01 && entry[2] == 0x02) {
            if (type_f_route != NULL) return 0;
            type_f_route = entry;
        }
        cursor += entry_length;
    }
    if (cursor != payload_length || !has_t3t_host_route ||
        type_f_route == NULL)
        return 0;
    type_f_route[0] = 0x00;
    uint16_t updated_crc = transport_crc16(buffer, frame_length);
    buffer[frame_length] = (uint8_t)(updated_crc >> 8);
    buffer[frame_length + 1] = (uint8_t)updated_crc;
    return 1;
}

static unsigned enable_emulated_felica_host_feature(uint8_t *buffer,
                                                     uint16_t *length) {
    // NXP's Felica-on-DH implementation sets LF_CON_ADV_FEAT (0x55) to 1.
    // Apple's follow-up discovery config ends with A08F=0. Replace only that
    // exact, final vendor TLV. The standard TLV is one byte shorter, so this
    // transformation only shrinks the existing writable packet.
    if (gEmulatedSession.load(std::memory_order_relaxed) == 0 ||
        !profile_is_active() ||
        buffer == NULL || length == NULL ||
        *length < 7 || (buffer[0] & 0xe0) != 0x20 ||
        (buffer[0] & 0x0f) != 0 || (buffer[1] & 0x3f) != 2)
        return 0;
    size_t payload_length = buffer[2];
    size_t frame_length = 3 + payload_length;
    if (payload_length < 5 || frame_length + 2 != *length)
        return 0;
    uint16_t original_crc = transport_crc16(buffer, frame_length);
    if (buffer[frame_length] != (uint8_t)(original_crc >> 8) ||
        buffer[frame_length + 1] != (uint8_t)original_crc)
        return 0;

    uint8_t *payload = buffer + 3;
    uint8_t count = payload[0];
    size_t cursor = 1;
    uint8_t *vendor_parameter = NULL;
    int has_disabled_lf_protocol = 0;
    for (uint8_t index = 0; index < count; ++index) {
        size_t parameter_start = cursor;
        if (cursor + 2 > payload_length) return 0;
        uint16_t identifier = payload[cursor++];
        if (identifier == 0xa0) {
            if (cursor + 2 > payload_length) return 0;
            identifier = (uint16_t)(0xa000 | payload[cursor++]);
        }
        uint8_t value_length = payload[cursor++];
        if (cursor + value_length > payload_length) return 0;
        uint8_t *value = payload + cursor;
        if (identifier == 0x50 && value_length == 1 && value[0] == 0)
            has_disabled_lf_protocol = 1;
        if (identifier == 0xa08f && value_length == 1 && value[0] == 0 &&
            cursor + value_length == payload_length)
            vendor_parameter = payload + parameter_start;
        cursor += value_length;
    }
    if (cursor != payload_length || !has_disabled_lf_protocol ||
        vendor_parameter == NULL)
        return 0;

    vendor_parameter[0] = 0x55;
    vendor_parameter[1] = 0x01;
    vendor_parameter[2] = 0x01;
    size_t updated_payload_length = payload_length - 1;
    buffer[2] = (uint8_t)updated_payload_length;
    size_t updated_frame_length = 3 + updated_payload_length;
    uint16_t updated_crc = transport_crc16(buffer, updated_frame_length);
    buffer[updated_frame_length] = (uint8_t)(updated_crc >> 8);
    buffer[updated_frame_length + 1] = (uint8_t)updated_crc;
    *length = (uint16_t)(updated_frame_length + 2);
    return 1;
}

static uint32_t observed_tml_write(void *tml_context, const uint8_t *buffer,
                                   uint16_t length, void *callback,
                                   void *user_context) {
    uint16_t effective_length = length;
    uint16_t system_code = 0;
    unsigned rewritten = rewrite_emulated_t3t_system_code(
        (uint8_t *)(uintptr_t)buffer, &effective_length, &system_code);
    if (rewritten != 0)
        gEmulatedSession.store(1, std::memory_order_relaxed);
    unsigned route_rewritten = rewrite_emulated_type_f_route_to_host(
        (uint8_t *)(uintptr_t)buffer, effective_length);
    unsigned feature_enabled = enable_emulated_felica_host_feature(
        (uint8_t *)(uintptr_t)buffer, &effective_length);
    unsigned map_rewritten = rewrite_emulated_t3t_discover_map(
        (uint8_t *)(uintptr_t)buffer, effective_length);
    if (buffer != NULL && effective_length >= 3 &&
        (buffer[0] & 0xe0) == 0) {
        size_t payload_length = buffer[2];
        size_t available = effective_length - 3;
        if (payload_length > available) payload_length = available;
        const uint8_t *payload = buffer + 3;
        if (contains_active_idm(payload, payload_length)) {
            append_line("event=nci-data-write connId=%u payloadLen=%zu "
                        "emulated=yes redacted=yes", buffer[0] & 0x0f,
                        payload_length);
        }
    }
    const char *command = relevant_command(buffer, effective_length);
    uint32_t sequence = 0;
    if (command != NULL) {
        sequence = __sync_add_and_fetch(&gSequence, 1);
        if (rewritten != 0) {
            append_line("event=nci-emulated-system-code-rewrite seq=%u "
                        "count=%u systemCode=%04X flags=0100 "
                        "removedDuplicateIds=3", sequence, rewritten,
                        system_code);
        }
        if (route_rewritten != 0) {
            append_line("event=nci-emulated-type-f-route-rewrite seq=%u "
                        "from=C0 to=00", sequence);
        }
        if (feature_enabled != 0) {
            append_line("event=nci-emulated-felica-host-feature seq=%u "
                        "from=A08F00 to=550101", sequence);
        }
        if (map_rewritten != 0) {
            append_line("event=nci-emulated-discover-map-rewrite seq=%u "
                        "from=800180 to=030201", sequence);
        }
        log_command(sequence, command, buffer, effective_length);
    }
    uint32_t result = gOriginalWrite(tml_context, buffer, effective_length,
                                     callback, user_context);
    if (command != NULL) {
        append_line("event=nci-write-return seq=%u status=0x%02X",
                    sequence, result & 0xff);
    }
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

extern "C" void NFCFInitializeNCIObserver(void) {
    NFCFResetBoundedAppendLog(&gLog);

    void *nfc_symbol = dlsym(RTLD_DEFAULT,
                              "phLibNfc_Mgt_ConfigRoutingTable");
    Dl_info nfc_info = {};
    int nfc_has_info = nfc_symbol != NULL ? dladdr(nfc_symbol, &nfc_info) : 0;
    if (nfc_symbol == NULL || nfc_has_info == 0 ||
        nfc_info.dli_fbase == NULL ||
        (uintptr_t)nfc_symbol - (uintptr_t)nfc_info.dli_fbase !=
            nfcf_backend::nfc_offsets::kLibNFCConfigRouting ||
        !nfcf_backend::MatchesReadableMemory(
            nfc_symbol, kExpectedLibNFCPrologue,
            sizeof(kExpectedLibNFCPrologue))) {
        append_line("observer=refused reason=libnfc-image-mismatch");
        return;
    }

    void *tml_write = dlsym(RTLD_DEFAULT, "phTmlNfc_Write");
    Dl_info tml_info = {};
    int tml_has_info = tml_write != NULL ? dladdr(tml_write, &tml_info) : 0;
    if (tml_write == NULL || tml_has_info == 0 ||
        tml_info.dli_fbase == NULL ||
        (uintptr_t)tml_write - (uintptr_t)tml_info.dli_fbase !=
            nfcf_backend::nfc_offsets::kTmlWriteExport ||
        !nfcf_backend::MatchesReadableMemory(
            tml_write, kExpectedTmlWritePrologue,
            sizeof(kExpectedTmlWritePrologue))) {
        append_line("observer=refused reason=tml-export-mismatch");
        return;
    }

    uint8_t *nfc_base = (uint8_t *)nfc_info.dli_fbase;
    uint8_t *common_island = NULL;
    for (size_t index = 0;
         index < sizeof(kWriteCallsites) / sizeof(kWriteCallsites[0]);
        ++index) {
        uint8_t *callsite = nfc_base + kWriteCallsites[index].offset;
        if (!nfcf_backend::MatchesReadableMemory(
                callsite, kWriteCallsites[index].expected,
                sizeof(kWriteCallsites[index].expected))) {
            append_line("observer=refused reason=tml-callsite-%zu-mismatch",
                        index);
            return;
        }
        uint8_t *target = decode_bl_target(callsite);
        if (common_island == NULL) common_island = target;
        if (target != common_island) {
            append_line("observer=refused reason=tml-call-target-%zu-mismatch",
                        index);
            return;
        }
    }
    if (common_island == NULL ||
        !nfcf_backend::MatchesReadableMemory(
            common_island, kExpectedTmlWriteIsland,
            sizeof(kExpectedTmlWriteIsland)) ||
        decode_adrp_add_target(common_island) != tml_write) {
        append_line("observer=refused reason=tml-common-island-mismatch");
        return;
    }

    uint8_t *local_stub =
        nfc_base + nfcf_backend::nfc_offsets::kTmlWriteLocalStub;
    if (!nfcf_backend::MatchesReadableMemory(
            local_stub, kExpectedTmlWriteLocalStub,
            sizeof(kExpectedTmlWriteLocalStub))) {
        append_line("observer=refused reason=tml-local-stub-mismatch");
        return;
    }
    void **write_slot = decode_adrp_ldr_slot(local_stub);
    if (!nfcf_backend::IsReadableMemory(write_slot, sizeof(*write_slot))) {
        append_line("observer=refused reason=tml-binding-unreadable");
        return;
    }
    void *bound_target = NULL;
    memcpy(&bound_target, write_slot, sizeof(bound_target));
    if (bound_target != tml_write) {
        append_line("observer=refused reason=tml-local-binding-mismatch");
        return;
    }

    gOriginalWrite = (TmlWriteFn)tml_write;
    size_t patched = 0;
    int result = 0;
    for (; patched < sizeof(kWriteCallsites) / sizeof(kWriteCallsites[0]);
         ++patched) {
        uint8_t *callsite = nfc_base + kWriteCallsites[patched].offset;
        uint32_t original = 0;
        uint32_t replacement = 0;
        memcpy(&original, kWriteCallsites[patched].expected,
               sizeof(original));
        result = encode_bl(callsite, local_stub, &replacement);
        if (result == 0)
            result = replace_code_word(callsite, original, replacement);
        if (result != 0) break;
    }
    if (result == 0) {
        result = replace_pointer(write_slot, tml_write,
                                 (void *)observed_tml_write);
    }
    if (result != 0) {
        while (patched > 0) {
            --patched;
            uint8_t *callsite = nfc_base + kWriteCallsites[patched].offset;
            uint32_t original = 0;
            uint32_t replacement = 0;
            memcpy(&original, kWriteCallsites[patched].expected,
                   sizeof(original));
            if (encode_bl(callsite, local_stub, &replacement) == 0)
                (void)replace_code_word(callsite, replacement, original);
        }
        gOriginalWrite = NULL;
        append_line("observer=failed reason=tml-local-route-patch code=%d",
                    result);
        return;
    }
    append_line("observer=installed method=guarded-local-stub callsites=%zu "
                "stub=0x%lx export=0x%lx",
                sizeof(kWriteCallsites) / sizeof(kWriteCallsites[0]),
                (unsigned long)nfcf_backend::nfc_offsets::kTmlWriteLocalStub,
                (unsigned long)nfcf_backend::nfc_offsets::kTmlWriteExport);
}
