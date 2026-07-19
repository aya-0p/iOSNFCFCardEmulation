#include "../Sources/Core/NFCFProfileRecord.hpp"
#include "../Sources/Core/NFCFProtocol.hpp"

#include <assert.h>
#include <atomic>
#include <stdio.h>
#include <string.h>
#include <thread>

using nfcf::Dispatch;
using nfcf::DispatchStatus;

static nfcf::Profile MakeProfile(uint8_t suffix, uint8_t block_count = 4) {
    nfcf::Profile profile = {};
    profile.system_code = static_cast<uint16_t>(0x1200 | suffix);
    profile.service_code = static_cast<uint16_t>(0x3400 | suffix);
    const uint8_t idm[8] = {0x02, 0x12, 0x34, 0x56,
                            0x78, 0x9a, 0xbc, suffix};
    const uint8_t pmm[6] = {1, 2, 3, 4, 5, suffix};
    memcpy(profile.idm, idm, sizeof(idm));
    memcpy(profile.pmm_tail, pmm, sizeof(pmm));
    profile.block_count = block_count;
    for (size_t block = 0; block < nfcf::kMaximumBlockCount; ++block) {
        for (size_t byte = 0; byte < nfcf::kBlockSize; ++byte) {
            profile.blocks[block][byte] =
                static_cast<uint8_t>(block * nfcf::kBlockSize + byte + suffix);
        }
    }
    return profile;
}

static void PutIdentityAndService(uint8_t *request,
                                  const nfcf::Profile &profile) {
    memcpy(request + 2, profile.idm, sizeof(profile.idm));
    request[10] = 1;
    request[11] = static_cast<uint8_t>(profile.service_code & 0xff);
    request[12] = static_cast<uint8_t>(profile.service_code >> 8);
}

static void TestProfileValidation() {
    auto profile = MakeProfile(1);
    assert(nfcf::IsValidProfile(profile));
    profile.block_count = 0;
    assert(!nfcf::IsValidProfile(profile));
    assert(!nfcf::SetActiveProfile(profile));
    profile.block_count = nfcf::kMaximumBlockCount + 1;
    assert(!nfcf::IsValidProfile(profile));
}

static void TestInactiveProfileDoesNotRespond() {
    nfcf::ClearActiveProfile();
    uint8_t request[10] = {10, 0x04, 0x02, 0x12, 0x34, 0x56, 0x78, 0x9a,
                           0xbc, 1};
    uint8_t response[128] = {};
    assert(Dispatch(request, sizeof(request), response, sizeof(response)).status ==
           DispatchStatus::kNoResponse);
    nfcf::Profile profile = {};
    assert(!nfcf::CopyActiveProfile(&profile));
}

static void TestRequestResponse() {
    const auto profile = MakeProfile(2);
    assert(nfcf::SetActiveProfile(profile));
    uint8_t request[10] = {10, 0x04};
    memcpy(request + 2, profile.idm, sizeof(profile.idm));
    uint8_t response[128] = {};
    const auto result = Dispatch(request, sizeof(request), response,
                                 sizeof(response));
    assert(result.status == DispatchStatus::kResponse);
    assert(result.request_command == 0x04 && result.response_length == 11);
    assert(response[1] == 0x05 && response[10] == 0x00);
    assert(memcmp(response + 2, profile.idm, sizeof(profile.idm)) == 0);
}

static void TestReadShortBlockList() {
    const auto profile = MakeProfile(7);
    assert(nfcf::SetActiveProfile(profile));
    uint8_t request[22] = {22, 0x06};
    PutIdentityAndService(request, profile);
    request[13] = 4;
    for (uint8_t block = 0; block < 4; ++block) {
        request[14 + block * 2] = 0x80;
        request[15 + block * 2] = block;
    }
    uint8_t response[128] = {};
    const auto result = Dispatch(request, sizeof(request), response,
                                 sizeof(response));
    assert(result.status == DispatchStatus::kResponse);
    assert(result.response_length == 77 && response[12] == 4);
    assert(memcmp(response + 13, profile.blocks,
                  4 * nfcf::kBlockSize) == 0);
}

static void TestReadLongBlockList() {
    const auto profile = MakeProfile(8, 2);
    assert(nfcf::SetActiveProfile(profile));
    uint8_t request[17] = {17, 0x06};
    PutIdentityAndService(request, profile);
    request[13] = 1;
    request[14] = 0x00;
    request[15] = 1;
    request[16] = 0;
    uint8_t response[64] = {};
    const auto result = Dispatch(request, sizeof(request), response,
                                 sizeof(response));
    assert(result.status == DispatchStatus::kResponse);
    assert(result.response_length == 29 && response[12] == 1);
    assert(memcmp(response + 13, profile.blocks[1], nfcf::kBlockSize) == 0);
}

static void TestMalformedRequestsAreRefused() {
    const auto profile = MakeProfile(3, 2);
    assert(nfcf::SetActiveProfile(profile));
    uint8_t request[16] = {16, 0x06};
    PutIdentityAndService(request, profile);
    request[13] = 1;
    request[14] = 0x80;
    request[15] = 0;
    uint8_t response[128] = {};

    request[0] = 15;
    assert(Dispatch(request, sizeof(request), response, sizeof(response)).status ==
           DispatchStatus::kNoResponse);
    request[0] = 16;
    request[11] ^= 1;
    assert(Dispatch(request, sizeof(request), response, sizeof(response)).status ==
           DispatchStatus::kNoResponse);
    request[11] ^= 1;
    request[14] = 0x81;
    assert(Dispatch(request, sizeof(request), response, sizeof(response)).status ==
           DispatchStatus::kNoResponse);
    request[14] = 0x90;
    assert(Dispatch(request, sizeof(request), response, sizeof(response)).status ==
           DispatchStatus::kNoResponse);
    request[14] = 0x80;
    request[15] = 2;
    assert(Dispatch(request, sizeof(request), response, sizeof(response)).status ==
           DispatchStatus::kNoResponse);
}

static void TestWireRecordRoundTrip() {
    nfcf::Profile profile = MakeProfile(9, 2);
    memset(profile.blocks[3], 0xa5, nfcf::kBlockSize);
    nfcf::ProfileRecord record = {};
    assert(nfcf::MakeProfileRecord(profile, &record));
    uint8_t encoded[nfcf::kProfileRecordEncodedSize] = {};
    assert(nfcf::EncodeProfileRecord(record, encoded, sizeof(encoded)));
    assert(sizeof(encoded) == 99);
    assert(memcmp(encoded, "NFCFPROF", 8) == 0);
    assert(encoded[8] == 1 && encoded[9] == 0 && encoded[10] == 0 &&
           encoded[11] == 0);
    assert(encoded[12] == 0x09 && encoded[13] == 0x12);
    assert(encoded[14] == 0x09 && encoded[15] == 0x34);
    assert(encoded[30] == 2);
    for (size_t index = 31 + 2 * nfcf::kBlockSize; index < 95; ++index)
        assert(encoded[index] == 0);

    nfcf::ProfileRecord decoded = {};
    assert(nfcf::DecodeProfileRecordBytes(encoded, sizeof(encoded), &decoded));
    nfcf::Profile round_trip = {};
    assert(nfcf::DecodeProfileRecord(decoded, &round_trip));
    assert(round_trip.system_code == profile.system_code);
    assert(round_trip.service_code == profile.service_code);
    assert(round_trip.block_count == profile.block_count);
    assert(memcmp(round_trip.idm, profile.idm, sizeof(profile.idm)) == 0);
    encoded[40] ^= 1;
    assert(!nfcf::DecodeProfileRecordBytes(encoded, sizeof(encoded), &decoded));
}

static void TestConcurrentProfileSnapshots() {
    const auto first = MakeProfile(0x11);
    const auto second = MakeProfile(0x22);
    assert(nfcf::SetActiveProfile(first));
    std::atomic<bool> stop{false};
    std::thread writer([&] {
        for (size_t index = 0; index < 20000; ++index)
            assert(nfcf::SetActiveProfile((index & 1) == 0 ? first : second));
        stop.store(true, std::memory_order_release);
    });
    while (!stop.load(std::memory_order_acquire)) {
        nfcf::Profile copied = {};
        assert(nfcf::CopyActiveProfile(&copied));
        const bool is_first = memcmp(copied.idm, first.idm, 8) == 0;
        const bool is_second = memcmp(copied.idm, second.idm, 8) == 0;
        assert(is_first || is_second);
    }
    writer.join();
}

int main() {
    TestProfileValidation();
    TestInactiveProfileDoesNotRespond();
    TestRequestResponse();
    TestReadShortBlockList();
    TestReadLongBlockList();
    TestMalformedRequestsAreRefused();
    TestWireRecordRoundTrip();
    TestConcurrentProfileSnapshots();
    nfcf::ClearActiveProfile();
    puts("nfcf_protocol_test: PASS");
    return 0;
}
