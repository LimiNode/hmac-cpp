#ifndef HMAC_CPP_PAGE_LOCK_REGISTRY_HPP
#define HMAC_CPP_PAGE_LOCK_REGISTRY_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>

namespace hmac_cpp {
namespace detail {

/// \brief Process-wide ownership registry for page-granular memory locks.
/// \tparam PageLocker Type exposing lock_page() and unlock_page().
template<class PageLocker>
class page_lock_registry {
public:
    explicit page_lock_registry(std::size_t page_size, PageLocker locker = PageLocker())
        : page_size_(page_size), locker_(locker) {}

    bool lock(void* ptr, std::size_t len) noexcept {
        std::uintptr_t first = 0;
        std::uintptr_t last = 0;
        if (!normalize(ptr, len, first, last)) {
            return false;
        }

        std::lock_guard<std::mutex> guard(mutex_);
        return lock_range(first, last);
    }

    bool unlock(void* ptr, std::size_t len) noexcept {
        std::uintptr_t first = 0;
        std::uintptr_t last = 0;
        if (!normalize(ptr, len, first, last)) {
            return false;
        }

        std::lock_guard<std::mutex> guard(mutex_);
        if (!all_pages_registered(first, last)) {
            return false;
        }

        bool success = true;
        for_each_page(first, last, [this, &success](std::uintptr_t page) {
            typename refcounts_type::iterator entry = refcounts_.find(page);
            if (entry->second > 1) {
                --entry->second;
                return true;
            }
            if (!locker_.unlock_page(reinterpret_cast<void*>(page), page_size_)) {
                success = false;
                return true;
            }
            refcounts_.erase(entry);
            return true;
        });
        return success;
    }

private:
    using refcounts_type = std::map<std::uintptr_t, std::size_t>;

    static std::size_t pending_count() noexcept {
        return std::numeric_limits<std::size_t>::max();
    }

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
    void for_each_page(std::uintptr_t first, std::uintptr_t last, Visitor visitor) noexcept {
        for (std::uintptr_t page = first;; page += page_size_) {
            if (!visitor(page) || page == last) {
                return;
            }
        }
    }

    bool all_pages_registered(std::uintptr_t first, std::uintptr_t last) const noexcept {
        for (std::uintptr_t page = first;; page += page_size_) {
            const typename refcounts_type::const_iterator entry = refcounts_.find(page);
            if (entry == refcounts_.end() || entry->second == 0 || entry->second == pending_count()) {
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
                refcounts_.emplace(page, 0);
                return true;
            });
        } catch (...) {
            erase_unlocked_pages(first, last);
            return false;
        }

        bool overflow = false;
        for_each_page(first, last, [this, &overflow](std::uintptr_t page) {
            const typename refcounts_type::const_iterator entry = refcounts_.find(page);
            if (entry->second >= pending_count() - 1) {
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
            typename refcounts_type::iterator entry = refcounts_.find(page);
            if (entry->second != 0) {
                return true;
            }
            if (!locker_.lock_page(reinterpret_cast<void*>(page), page_size_)) {
                return false;
            }
            entry->second = pending_count();
            return true;
        });

        if (has_unlocked_page(first, last)) {
            rollback_pending_locks(first, last);
            return false;
        }

        for_each_page(first, last, [this](std::uintptr_t page) {
            typename refcounts_type::iterator entry = refcounts_.find(page);
            entry->second = entry->second == pending_count() ? 1 : entry->second + 1;
            return true;
        });
        return true;
    }

    bool has_unlocked_page(std::uintptr_t first, std::uintptr_t last) const noexcept {
        for (std::uintptr_t page = first;; page += page_size_) {
            const typename refcounts_type::const_iterator entry = refcounts_.find(page);
            if (entry == refcounts_.end() || entry->second == 0) {
                return true;
            }
            if (page == last) {
                return false;
            }
        }
    }

    void erase_unlocked_pages(std::uintptr_t first, std::uintptr_t last) noexcept {
        for_each_page(first, last, [this](std::uintptr_t page) {
            typename refcounts_type::iterator entry = refcounts_.find(page);
            if (entry != refcounts_.end() && entry->second == 0) {
                refcounts_.erase(entry);
            }
            return true;
        });
    }

    void rollback_pending_locks(std::uintptr_t first, std::uintptr_t last) noexcept {
        for_each_page(first, last, [this](std::uintptr_t page) {
            typename refcounts_type::iterator entry = refcounts_.find(page);
            if (entry == refcounts_.end()) {
                return true;
            }
            if (entry->second == pending_count()) {
                if (locker_.unlock_page(reinterpret_cast<void*>(page), page_size_)) {
                    refcounts_.erase(entry);
                } else {
                    entry->second = 1;
                }
            } else if (entry->second == 0) {
                refcounts_.erase(entry);
            }
            return true;
        });
    }

    std::size_t page_size_{};
    PageLocker locker_;
    refcounts_type refcounts_;
    std::mutex mutex_;
};

} // namespace detail
} // namespace hmac_cpp

#endif // HMAC_CPP_PAGE_LOCK_REGISTRY_HPP
