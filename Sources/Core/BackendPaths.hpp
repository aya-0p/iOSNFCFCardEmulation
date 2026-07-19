#pragma once

namespace nfcf_backend {

inline constexpr const char *kStateDirectory =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation";
inline constexpr const char *kCommandRequestPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/command.request";
inline constexpr const char *kProfileRecordPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/profile.record";

inline constexpr const char *kObserverResultPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/nci-read.log";
inline constexpr const char *kObserverReadyPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/nci-read.ready";
inline constexpr const char *kNCIObserverResultPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/nci.log";
inline constexpr const char *kStackObserverResultPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/stack.log";
inline constexpr const char *kProfileResultPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/profile.result";
inline constexpr const char *kProfileReadyPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/profile.ready";
inline constexpr const char *kPrewarmResultPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/prewarm.result";
inline constexpr const char *kRoutingResultPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/routing.result";
inline constexpr const char *kSetCEResultPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/setce.result";
inline constexpr const char *kRoutePatchResultPath =
    "/var/mobile/Library/Caches/org.hoshitsugi.iosnfcfcardemulation/t3t-route.result";
}  // namespace nfcf_backend
