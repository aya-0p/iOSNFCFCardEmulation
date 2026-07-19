#pragma once

#include <stdint.h>

namespace nfcf_backend::nfc_offsets {

// These offsets are accepted only when the mapped address and expected
// instruction bytes also match at runtime.
inline constexpr uintptr_t kNFDriverSetConfiguration = 0x2ac6c;
inline constexpr uintptr_t kSetCEConfig = 0x123e4;
inline constexpr uintptr_t kWait = 0x1abc8;
inline constexpr uintptr_t kRelease = 0x1aa64;
inline constexpr uintptr_t kHostProtocolInstruction = 0x28720;
inline constexpr uintptr_t kLibNFCConfigRouting = 0x6e8c0;
inline constexpr uintptr_t kTmlReadLocalStub = 0xba970;
inline constexpr uintptr_t kTmlReadExport = 0x3dc8;
inline constexpr uintptr_t kTmlWriteLocalStub = 0xba9ac;
inline constexpr uintptr_t kTmlWriteExport = 0x83e0;

}  // namespace nfcf_backend::nfc_offsets
