#pragma once

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace nfcf_backend {

inline bool IsReadableMemory(const void *address, size_t length) {
    if (address == nullptr || length == 0) return false;

    uintptr_t start = reinterpret_cast<uintptr_t>(address);
    if (start > UINTPTR_MAX - length) return false;
    uintptr_t end = start + length;

    vm_address_t region_start = static_cast<vm_address_t>(start);
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info = {};
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t result = vm_region_64(
        mach_task_self(), &region_start, &region_size,
        VM_REGION_BASIC_INFO_64,
        reinterpret_cast<vm_region_info_t>(&info), &info_count,
        &object_name);
    if (object_name != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object_name);
    if (result != KERN_SUCCESS || (info.protection & VM_PROT_READ) == 0)
        return false;

    uintptr_t mapped_start = static_cast<uintptr_t>(region_start);
    if (mapped_start > UINTPTR_MAX - static_cast<uintptr_t>(region_size))
        return false;
    uintptr_t mapped_end = mapped_start + static_cast<uintptr_t>(region_size);
    return mapped_start <= start && end <= mapped_end;
}

inline bool MatchesReadableMemory(const void *address,
                                  const void *expected,
                                  size_t length) {
    return expected != nullptr && IsReadableMemory(address, length) &&
           memcmp(address, expected, length) == 0;
}

}  // namespace nfcf_backend
