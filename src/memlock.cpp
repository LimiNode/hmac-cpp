#include "hmac_cpp/memlock.hpp"
#include "hmac_cpp/page_lock_registry.hpp"

#if defined(HMAC_CPP_ENABLE_MLOCK)

#if defined(_WIN32)
#include <windows.h>
namespace {
struct os_page_locker {
    bool lock_page(void* ptr, size_t len) const noexcept { return VirtualLock(ptr, len) != 0; }
    bool unlock_page(void* ptr, size_t len) const noexcept { return VirtualUnlock(ptr, len) != 0; }
};

size_t system_page_size() noexcept {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    return static_cast<size_t>(info.dwPageSize);
}

hmac_cpp::detail::page_lock_registry<os_page_locker>& registry() {
    static hmac_cpp::detail::page_lock_registry<os_page_locker> value(system_page_size());
    return value;
}
}
namespace hmac_cpp {
bool lock_pages(void* ptr, size_t len) noexcept   { return registry().lock(ptr, len); }
bool unlock_pages(void* ptr, size_t len) noexcept { return registry().unlock(ptr, len); }
}

#else
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

namespace {
struct os_page_locker {
    bool lock_page(void* ptr, size_t len) const noexcept { return ::mlock(ptr, len) == 0; }
    bool unlock_page(void* ptr, size_t len) const noexcept { return ::munlock(ptr, len) == 0; }
};

size_t system_page_size() noexcept {
    const long value = sysconf(_SC_PAGESIZE);
    return value > 0 ? static_cast<size_t>(value) : 0;
}

hmac_cpp::detail::page_lock_registry<os_page_locker>& registry() {
    static hmac_cpp::detail::page_lock_registry<os_page_locker> value(system_page_size());
    return value;
}
}

namespace hmac_cpp {
bool lock_pages(void* ptr, size_t len) noexcept {
    return registry().lock(ptr, len);
}
bool unlock_pages(void* ptr, size_t len) noexcept {
    return registry().unlock(ptr, len);
}
}

#endif

#else // !HMAC_CPP_ENABLE_MLOCK

namespace hmac_cpp {
bool lock_pages(void* ptr, size_t len) noexcept   { (void)ptr; (void)len; return false; }
bool unlock_pages(void* ptr, size_t len) noexcept { (void)ptr; (void)len; return false; }
}

#endif // HMAC_CPP_ENABLE_MLOCK
