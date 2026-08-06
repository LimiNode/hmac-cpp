#ifndef HMAC_CPP_PAGE_LOCK_REGISTRY_HPP
#define HMAC_CPP_PAGE_LOCK_REGISTRY_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <utility>

namespace hmac_cpp {
namespace detail {

struct page_lock_page_state {
    std::size_t owners{};
    bool os_locked{};
    bool pending_lock{};
};

/// \brief Process-wide ownership registry for page-granular memory locks.
/// \tparam PageLocker Type exposing lock_page() and unlock_page().
/// \tparam Mutex Mutex type used to synchronize access to the registry.
/// \tparam PageStateAllocator Allocator used by the registry's page-state map.
template<class PageLocker,
         class Mutex = std::mutex,
         class PageStateAllocator = std::allocator<std::pair<const std::uintptr_t, page_lock_page_state>>>
class page_lock_registry {
public:
    static_assert(noexcept(std::declval<PageLocker&>().lock_page(nullptr, std::size_t{})),
                  "PageLocker::lock_page must be noexcept");
    static_assert(noexcept(std::declval<PageLocker&>().unlock_page(nullptr, std::size_t{})),
                  "PageLocker::unlock_page must be noexcept");

    explicit page_lock_registry(std::size_t page_size, PageLocker locker = PageLocker())
        : page_size_(page_size), locker_(locker) {}

    bool lock(void* ptr, std::size_t len) noexcept {
        std::uintptr_t first = 0;
        std::uintptr_t last = 0;
        if (!normalize(ptr, len, first, last)) {
            return false;
        }

        try {
            std::lock_guard<Mutex> guard(mutex_);
            return lock_range(first, last);
        } catch (...) {
            return false;
        }
    }

    bool unlock(void* ptr, std::size_t len) noexcept {
        std::uintptr_t first = 0;
        std::uintptr_t last = 0;
        if (!normalize(ptr, len, first, last)) {
            return false;
        }

        try {
            std::lock_guard<Mutex> guard(mutex_);
            if (!all_pages_owned(first, last)) {
                return false;
            }

            bool success = true;
            for_each_page(first, last, [this, &success](std::uintptr_t page) {
                typename page_states_type::iterator entry = page_states_.find(page);
                page_state& state = entry->second;
                if (state.owners > 1) {
                    --state.owners;
                    return true;
                }

                state.owners = 0;
                if (!state.os_locked || locker_.unlock_page(reinterpret_cast<void*>(page), page_size_)) {
                    page_states_.erase(entry);
                } else {
                    success = false;
                }
                return true;
            });
            return success;
        } catch (...) {
            return false;
        }
    }

private:
    using page_state = page_lock_page_state;
    using page_states_type = std::map<std::uintptr_t,
                                     page_state,
                                     std::less<std::uintptr_t>,
                                     PageStateAllocator>;

    bool normalize(void* ptr, std::size_t len, std::uintptr_t& first,
                   std::uintptr_t& last) const noexcept {
        if (ptr == nullptr || len == 0 || page_size_ == 0) {
            return false;
        }

        const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(ptr);
        if (len - 1 > std::numeric_limits<std::uintptr_t>::max() - address) {
            return false;
        }
        const std::uintptr_t end = address + len - 1;
        first = address - address % page_size_;
        last = end - end % page_size_;
        return true;
    }

    template<class Visitor>
    void for_each_page(std::uintptr_t first, std::uintptr_t last, Visitor visitor) {
        for (std::uintptr_t page = first;; page += page_size_) {
            if (!visitor(page) || page == last) {
                return;
            }
        }
    }

    bool all_pages_owned(std::uintptr_t first, std::uintptr_t last) const noexcept {
        for (std::uintptr_t page = first;; page += page_size_) {
            const typename page_states_type::const_iterator entry = page_states_.find(page);
            if (entry == page_states_.end() || entry->second.owners == 0 || entry->second.pending_lock) {
                return false;
            }
            if (page == last) {
                return true;
            }
        }
    }

    bool lock_range(std::uintptr_t first, std::uintptr_t last) noexcept {
        try {
            for_each_page(first, last, [this](std::uintptr_t page) {
                page_states_.emplace(page, page_state{});
                return true;
            });
        } catch (...) {
            erase_unlocked_pages(first, last);
            return false;
        }

        bool overflow = false;
        for_each_page(first, last, [this, &overflow](std::uintptr_t page) {
            const typename page_states_type::const_iterator entry = page_states_.find(page);
            if (entry->second.owners == std::numeric_limits<std::size_t>::max()) {
                overflow = true;
                return false;
            }
            return true;
        });
        if (overflow) {
            erase_unlocked_pages(first, last);
            return false;
        }

        for_each_page(first, last, [this](std::uintptr_t page) {
            typename page_states_type::iterator entry = page_states_.find(page);
            page_state& state = entry->second;
            if (state.owners != 0 || state.os_locked) {
                return true;
            }
            if (!locker_.lock_page(reinterpret_cast<void*>(page), page_size_)) {
                return false;
            }
            state.os_locked = true;
            state.pending_lock = true;
            return true;
        });

        if (has_unlocked_page(first, last)) {
            rollback_pending_locks(first, last);
            return false;
        }

        for_each_page(first, last, [this](std::uintptr_t page) {
            typename page_states_type::iterator entry = page_states_.find(page);
            ++entry->second.owners;
            entry->second.pending_lock = false;
            return true;
        });
        return true;
    }

    bool has_unlocked_page(std::uintptr_t first, std::uintptr_t last) const noexcept {
        for (std::uintptr_t page = first;; page += page_size_) {
            const typename page_states_type::const_iterator entry = page_states_.find(page);
            if (entry == page_states_.end() || (!entry->second.os_locked && entry->second.owners == 0)) {
                return true;
            }
            if (page == last) {
                return false;
            }
        }
    }

    void erase_unlocked_pages(std::uintptr_t first, std::uintptr_t last) noexcept {
        for_each_page(first, last, [this](std::uintptr_t page) {
            typename page_states_type::iterator entry = page_states_.find(page);
            if (entry != page_states_.end() && entry->second.owners == 0 && !entry->second.os_locked) {
                page_states_.erase(entry);
            }
            return true;
        });
    }

    void rollback_pending_locks(std::uintptr_t first, std::uintptr_t last) noexcept {
        for_each_page(first, last, [this](std::uintptr_t page) {
            typename page_states_type::iterator entry = page_states_.find(page);
            if (entry == page_states_.end()) {
                return true;
            }
            page_state& state = entry->second;
            if (state.pending_lock) {
                if (locker_.unlock_page(reinterpret_cast<void*>(page), page_size_)) {
                    page_states_.erase(entry);
                } else {
                    state.pending_lock = false;
                }
            } else if (state.owners == 0 && !state.os_locked) {
                page_states_.erase(entry);
            }
            return true;
        });
    }

    std::size_t page_size_{};
    PageLocker locker_;
    page_states_type page_states_;
    Mutex mutex_;
};

} // namespace detail
} // namespace hmac_cpp

#endif // HMAC_CPP_PAGE_LOCK_REGISTRY_HPP
