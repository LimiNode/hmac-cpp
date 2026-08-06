#ifndef HMAC_CPP_SECURE_BUFFER_HPP
#define HMAC_CPP_SECURE_BUFFER_HPP

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>
#include "hmac_cpp/memlock.hpp"

#if defined(HAVE_EXPLICIT_BZERO)
#include <strings.h>
#endif

// Macro to mark deprecated APIs in a compiler-portable way
#ifndef HMACCPP_DEPRECATED
#if defined(__clang__) || defined(__GNUC__)
#define HMACCPP_DEPRECATED(msg) __attribute__((deprecated(msg)))
#elif defined(_MSC_VER)
#define HMACCPP_DEPRECATED(msg) __declspec(deprecated(msg))
#else
#define HMACCPP_DEPRECATED(msg)
#endif
#endif

namespace hmac_cpp {

/// \brief Default page-locking policy used by secure_buffer.
struct page_locker {
    static bool lock(void* ptr, size_t len) noexcept { return lock_pages(ptr, len); }
    static bool unlock(void* ptr, size_t len) noexcept { return unlock_pages(ptr, len); }
};

/// \brief Securely zeroes a memory region.
/// \param ptr Pointer to the memory to wipe.
/// \param len Number of bytes to set to zero.
static inline void secure_zero(void* ptr, size_t len) {
#if defined(__STDC_LIB_EXT1__)
    (void)memset_s(ptr, len, 0, len);
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) {
        *p++ = 0;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
}

/// \brief Vector-like buffer that zeroizes its contents on destruction.
/// Page locking is best-effort: a failed lock leaves the buffer usable, and
/// is_locked() reports false. A successful lock always records its exact range.
/// \tparam T Trivial value type stored in the buffer (defaults to uint8_t).
/// \tparam LockOnAlloc Lock pages in memory on allocation.
/// \tparam Allocator Allocator used for the backing storage.
/// \tparam PageLocker Page-locking policy used when LockOnAlloc is true.
template<class T = uint8_t,
         bool LockOnAlloc = false,
         class Allocator = std::allocator<T>,
         class PageLocker = page_locker>
struct secure_buffer {
    static_assert(std::is_trivial<T>::value, "secure_buffer requires trivial type");

    using vector_type = std::vector<T, Allocator>;

    secure_buffer() = default;

    /// \brief Construct with n default-initialized elements.
    /// \param n Element count.
    explicit secure_buffer(size_t n) { replace_with_zeroed(n); }

    /// \brief Construct from vector, moving its contents.
    /// \param v Source vector.
    explicit secure_buffer(vector_type&& v) : buf(validate_and_move(v)) {
        lock_current_range();
    }

    /// \brief Construct from std::string rvalue and zeroize the source.
    /// \param s Source string.
    template<class U = T, typename std::enable_if<std::is_same<U, uint8_t>::value, int>::type = 0>
    explicit secure_buffer(std::string&& s) {
        string_wipe_guard source_wiper(s);
        assign(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    secure_buffer(const secure_buffer& other) { replace_with_copy(other.data(), other.size()); }

    secure_buffer& operator=(const secure_buffer& other) {
        if (this != &other) {
            replace_with_copy(other.data(), other.size());
        }
        return *this;
    }

    secure_buffer(secure_buffer&& other)
        : buf(std::move(other.buf)),
          locked_ptr_(other.locked_ptr_),
          locked_bytes_(other.locked_bytes_) {
        other.clear_locked_range();
    }

    secure_buffer& operator=(secure_buffer&& other) {
        if (this != &other) {
            if (buf.get_allocator() == other.buf.get_allocator()) {
                clear();
                buf = std::move(other.buf);
                locked_ptr_ = other.locked_ptr_;
                locked_bytes_ = other.locked_bytes_;
                other.clear_locked_range();
            } else {
                replace_with_copy(other.data(), other.size());
                other.clear();
            }
        }
        return *this;
    }

    /// \brief Zeroize contents on destruction.
    ~secure_buffer() noexcept { clear(); }

    /// \brief Check whether pages are locked.
    bool is_locked() const noexcept { return locked_ptr_ != nullptr; }

    /// \brief Clear and deallocate the buffer.
    void clear() noexcept {
        secure_zero(buf.data(), byte_count_noexcept(buf.size()));
        unlock_locked_range();
        vector_type empty(buf.get_allocator());
        buf.swap(empty);
    }

    /// \brief Resize the buffer, zeroizing data before a reallocation releases it.
    void resize(size_t n) {
        checked_byte_count(n);
        const size_t old_sz = buf.size();
        if (n <= old_sz) {
            if (n < old_sz) {
                secure_zero(buf.data() + n, byte_count_noexcept(old_sz - n));
            }
            buf.resize(n);
            return;
        }

        // std::vector::resize may release the old allocation before we can
        // wipe it. Allocate and lock the replacement first so the old secret
        // remains reachable until it has been zeroized and unlocked.
        replace_with_copy(buf.data(), old_sz, n);
    }

    /// \brief Assign from raw pointer.
    void assign(const T* p, size_t n) {
        replace_with_copy(p, n);
    }

    /// \brief Assign from std::string rvalue and zeroize the source.
    template<class U = T, typename std::enable_if<std::is_same<U, uint8_t>::value, int>::type = 0>
    void assign(std::string&& s) {
        string_wipe_guard source_wiper(s);
        assign(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    T* data() { return buf.data(); }
    const T* data() const { return buf.data(); }
    size_t size() const { return buf.size(); }

    T& operator[](size_t i) { return buf[i]; }
    const T& operator[](size_t i) const { return buf[i]; }

    typename vector_type::iterator begin() { return buf.begin(); }
    typename vector_type::iterator end() { return buf.end(); }
    typename vector_type::const_iterator begin() const { return buf.begin(); }
    typename vector_type::const_iterator end() const { return buf.end(); }

private:
    struct string_wipe_guard {
        explicit string_wipe_guard(std::string& value) noexcept : value_(value) {}
        ~string_wipe_guard() noexcept { wipe_string(value_); }

        std::string& value_;
    };

    struct replacement_guard {
        replacement_guard(void* ptr, size_t bytes) noexcept : ptr_(ptr), bytes_(bytes) {}

        ~replacement_guard() noexcept {
            if (!active_) {
                return;
            }
            secure_zero(ptr_, bytes_);
            if (locked_) {
                PageLocker::unlock(ptr_, bytes_);
            }
        }

        void lock() noexcept {
            if (LockOnAlloc && ptr_ != nullptr && bytes_ != 0) {
                locked_ = PageLocker::lock(ptr_, bytes_);
            }
        }

        bool release() noexcept {
            active_ = false;
            return locked_;
        }

        void* ptr_{};
        size_t bytes_{};
        bool locked_{};
        bool active_{true};
    };

    void lock_current_range() {
        if (LockOnAlloc && !buf.empty()) {
            const size_t bytes = checked_byte_count(buf.size());
            set_locked_range(buf.data(), bytes, PageLocker::lock(buf.data(), bytes));
        }
    }

    static size_t checked_byte_count(size_t count) {
        if (count > std::numeric_limits<size_t>::max() / sizeof(T)) {
            throw std::length_error("secure_buffer size exceeds addressable byte range");
        }
        return count * sizeof(T);
    }

    static size_t byte_count_noexcept(size_t count) noexcept {
        return count * sizeof(T);
    }

    static void wipe_string(std::string& value) noexcept {
        if (!value.empty()) {
            secure_zero(&value[0], value.size());
            value.clear();
        }
    }

    static vector_type validate_and_move(vector_type& source) {
        checked_byte_count(source.size());
        return std::move(source);
    }

    vector_type make_replacement(size_t n) {
        checked_byte_count(n);
        return vector_type(n, T{}, buf.get_allocator());
    }

    void replace_with_zeroed(size_t n) {
        vector_type replacement = make_replacement(n);
        replacement_guard guard(replacement.data(), checked_byte_count(replacement.size()));
        guard.lock();
        replace_with_replacement(replacement, guard);
    }

    void replace_with_copy(const T* source, size_t n) {
        replace_with_copy(source, n, n);
    }

    void replace_with_copy(const T* source, size_t source_size, size_t destination_size) {
        if (source == nullptr && source_size != 0) {
            throw std::invalid_argument("secure_buffer source cannot be null");
        }
        if (source_size > destination_size) {
            throw std::length_error("secure_buffer destination is smaller than source");
        }

        vector_type replacement = make_replacement(destination_size);
        replacement_guard guard(replacement.data(), checked_byte_count(replacement.size()));
        guard.lock();
        if (source_size != 0) {
            std::copy_n(source, source_size, replacement.begin());
        }
        replace_with_replacement(replacement, guard);
    }

    void replace_with_replacement(vector_type& replacement, replacement_guard& guard) {
        secure_zero(buf.data(), byte_count_noexcept(buf.size()));
        unlock_locked_range();
        buf.swap(replacement);
        set_locked_range(buf.data(), byte_count_noexcept(buf.size()), guard.release());
    }

    void unlock_locked_range() noexcept {
        if (locked_ptr_ != nullptr) {
            PageLocker::unlock(locked_ptr_, locked_bytes_);
        }
        clear_locked_range();
    }

    void set_locked_range(void* ptr, size_t bytes, bool locked) noexcept {
        if (locked) {
            locked_ptr_ = ptr;
            locked_bytes_ = bytes;
        } else {
            clear_locked_range();
        }
    }

    void clear_locked_range() noexcept {
        locked_ptr_ = nullptr;
        locked_bytes_ = 0;
    }

    vector_type buf;
    void* locked_ptr_{};
    size_t locked_bytes_{};
};

} // namespace hmac_cpp

#endif // HMAC_CPP_SECURE_BUFFER_HPP
