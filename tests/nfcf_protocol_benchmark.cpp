#include "../Sources/Core/NFCFProfileRecord.hpp"
#include "../Sources/Core/NFCFProtocol.hpp"

#include <chrono>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main() {
    nfcf::Profile profile = {};
    profile.system_code = 0x12fc;
    profile.service_code = 0x3a09;
    const uint8_t idm[8] = {0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 1};
    const uint8_t pmm[6] = {1, 2, 3, 4, 5, 6};
    memcpy(profile.idm, idm, sizeof(idm));
    memcpy(profile.pmm_tail, pmm, sizeof(pmm));
    profile.block_count = nfcf::kMaximumBlockCount;
    if (!nfcf::SetActiveProfile(profile)) return 1;

    uint8_t request[10] = {10, 0x04};
    memcpy(request + 2, idm, sizeof(idm));
    uint8_t response[128] = {};
    constexpr size_t iterations = 1000000;
    uint64_t checksum = 0;
    const auto started = std::chrono::steady_clock::now();
    for (size_t index = 0; index < iterations; ++index) {
        const auto result = nfcf::Dispatch(
            request, sizeof(request), response, sizeof(response));
        if (result.status != nfcf::DispatchStatus::kResponse) return 1;
        checksum += response[index % result.response_length];
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
    printf("dispatch_iterations=%zu ns_per_dispatch=%.2f checksum=%llu\n",
           iterations, static_cast<double>(nanoseconds) / iterations,
           static_cast<unsigned long long>(checksum));
    return 0;
}
