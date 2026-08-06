#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <system_error>

#include "hmac_cpp/page_lock_registry.hpp"
#include "hmac_cpp/secure_buffer.hpp"

namespace {

struct DeallocationRecord {
    const void* ptr{};
    std::size_t elements{};
    bool was_zeroed{};
};

struct RecordingAllocator {
    using value_type = std::uint8_t;

    template<class U>
    struct rebind {
        using other = RecordingAllocator;
    };

    RecordingAllocator() noexcept = default;

    template<class U>
    RecordingAllocator(const U&) noexcept {}

    std::uint8_t* allocate(std::size_t count) {
        return std::allocator<std::uint8_t>{}.allocate(count);
    }

    void deallocate(std::uint8_t* ptr, std::size_t count) noexcept {
        deallocations[deallocation_count++] = {
            ptr,
            count,
            std::all_of(ptr, ptr + count, [](std::uint8_t value) { return value == 0; })
        };
        std::allocator<std::uint8_t>{}.deallocate(ptr, count);
    }

    static void reset() noexcept { deallocation_count = 0; }

    static std::array<DeallocationRecord, 128> deallocations;
    static std::size_t deallocation_count;
};

bool operator==(const RecordingAllocator&, const RecordingAllocator&) noexcept { return true; }
bool operator!=(const RecordingAllocator&, const RecordingAllocator&) noexcept { return false; }

std::array<DeallocationRecord, 128> RecordingAllocator::deallocations{};
std::size_t RecordingAllocator::deallocation_count{};

template<class T>
struct StatefulAllocator {
    using value_type = T;

    template<class U>
    struct rebind {
        using other = StatefulAllocator<U>;
    };

    explicit StatefulAllocator(int value = 0) noexcept : id(value) {}
    StatefulAllocator(const StatefulAllocator&) noexcept = default;
    StatefulAllocator(StatefulAllocator&&) noexcept = default;
    StatefulAllocator& operator=(const StatefulAllocator&) noexcept = default;
    StatefulAllocator& operator=(StatefulAllocator&&) noexcept = default;

    template<class U>
    StatefulAllocator(const StatefulAllocator<U>& other) noexcept : id(other.id) {}

    T* allocate(std::size_t count) {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* ptr, std::size_t count) noexcept {
        std::allocator<T>{}.deallocate(ptr, count);
    }

    int id{};
};

template<class T, class U>
bool operator==(const StatefulAllocator<T>& lhs, const StatefulAllocator<U>& rhs) noexcept {
    return lhs.id == rhs.id;
}

template<class T, class U>
bool operator!=(const StatefulAllocator<T>& lhs, const StatefulAllocator<U>& rhs) noexcept {
    return !(lhs == rhs);
}

enum class PageLockEventType { Lock, Unlock };

struct PageLockEvent {
    PageLockEventType type{};
    void* ptr{};
    std::size_t bytes{};
    bool was_zeroed_at_lock{};
    bool was_zeroed_at_unlock{};
};

struct RecordingPageLocker {
    static bool lock(void* ptr, std::size_t bytes) noexcept {
        events[event_count++] = {
            PageLockEventType::Lock,
            ptr,
            bytes,
            std::all_of(static_cast<const std::uint8_t*>(ptr),
                        static_cast<const std::uint8_t*>(ptr) + bytes,
                        [](std::uint8_t value) { return value == 0; }),
            false
        };
        return lock_succeeds;
    }

    static bool unlock(void* ptr, std::size_t bytes) noexcept {
        events[event_count++] = {
            PageLockEventType::Unlock,
            ptr,
            bytes,
            false,
            std::all_of(static_cast<const std::uint8_t*>(ptr),
                        static_cast<const std::uint8_t*>(ptr) + bytes,
                        [](std::uint8_t value) { return value == 0; })
        };
        return true;
    }

    static void reset() noexcept { event_count = 0; }

    static std::array<PageLockEvent, 16> events;
    static std::size_t event_count;
    static bool lock_succeeds;
};

std::array<PageLockEvent, 16> RecordingPageLocker::events{};
std::size_t RecordingPageLocker::event_count{};
bool RecordingPageLocker::lock_succeeds{true};

struct ThrowingAllocator {
    using value_type = std::uint8_t;

    template<class U>
    struct rebind {
        using other = ThrowingAllocator;
    };

    ThrowingAllocator() noexcept = default;

    template<class U>
    ThrowingAllocator(const U&) noexcept {}

    std::uint8_t* allocate(std::size_t count) {
        if (fail_allocations) {
            throw std::bad_alloc();
        }
        return std::allocator<std::uint8_t>{}.allocate(count);
    }

    void deallocate(std::uint8_t* ptr, std::size_t count) noexcept {
        std::allocator<std::uint8_t>{}.deallocate(ptr, count);
    }

    static bool fail_allocations;
};

bool operator==(const ThrowingAllocator&, const ThrowingAllocator&) noexcept { return true; }
bool operator!=(const ThrowingAllocator&, const ThrowingAllocator&) noexcept { return false; }
bool ThrowingAllocator::fail_allocations{};

enum class RegistryEventType { Lock, Unlock };

struct RegistryEvent {
    RegistryEventType type{};
    void* page{};
};

struct RegistryPageLocker {
    bool lock_page(void* page, std::size_t) const noexcept {
        events[event_count++] = {RegistryEventType::Lock, page};
        return reinterpret_cast<std::uintptr_t>(page) != failing_page;
    }

    bool unlock_page(void* page, std::size_t) const noexcept {
        events[event_count++] = {RegistryEventType::Unlock, page};
        return reinterpret_cast<std::uintptr_t>(page) != failing_unlock_page;
    }

    static void reset() noexcept {
        event_count = 0;
        failing_page = 0;
        failing_unlock_page = 0;
    }

    static std::array<RegistryEvent, 16> events;
    static std::size_t event_count;
    static std::uintptr_t failing_page;
    static std::uintptr_t failing_unlock_page;
};

std::array<RegistryEvent, 16> RegistryPageLocker::events{};
std::size_t RegistryPageLocker::event_count{};
std::uintptr_t RegistryPageLocker::failing_page{};
std::uintptr_t RegistryPageLocker::failing_unlock_page{};

struct ThrowingMutex {
    void lock() {
        throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));
    }

    void unlock() noexcept {}
};

struct PageStateAllocationControl {
    static int successful_allocations_before_failure;
};

int PageStateAllocationControl::successful_allocations_before_failure{-1};

template<class T>
struct ThrowingPageStateAllocator {
    using value_type = T;

    ThrowingPageStateAllocator() noexcept = default;

    template<class U>
    ThrowingPageStateAllocator(const ThrowingPageStateAllocator<U>&) noexcept {}

    T* allocate(std::size_t count) {
        if (PageStateAllocationControl::successful_allocations_before_failure == 0) {
            throw std::bad_alloc();
        }
        if (PageStateAllocationControl::successful_allocations_before_failure > 0) {
            --PageStateAllocationControl::successful_allocations_before_failure;
        }
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* ptr, std::size_t count) noexcept {
        std::allocator<T>{}.deallocate(ptr, count);
    }
};

template<class T, class U>
bool operator==(const ThrowingPageStateAllocator<T>&,
                const ThrowingPageStateAllocator<U>&) noexcept {
    return true;
}

template<class T, class U>
bool operator!=(const ThrowingPageStateAllocator<T>& lhs,
                const ThrowingPageStateAllocator<U>& rhs) noexcept {
    return !(lhs == rhs);
}

using UnlockedBuffer = hmac_cpp::secure_buffer<std::uint8_t, false, RecordingAllocator>;
using LockedBuffer = hmac_cpp::secure_buffer<std::uint8_t,
                                              true,
                                              RecordingAllocator,
                                              RecordingPageLocker>;
using WideBuffer = hmac_cpp::secure_buffer<std::uint32_t,
                                            true,
                                            std::allocator<std::uint32_t>,
                                            RecordingPageLocker>;
using StatefulBuffer = hmac_cpp::secure_buffer<std::uint8_t,
                                                true,
                                                StatefulAllocator<std::uint8_t>,
                                                RecordingPageLocker>;
using ThrowingBuffer = hmac_cpp::secure_buffer<std::uint8_t, false, ThrowingAllocator>;

TEST(SecureBufferTest, ResizeGrowthWipesOldAllocationBeforeDeallocate) {
    UnlockedBuffer buffer(8);
    for (std::size_t index = 0; index < buffer.size(); ++index) {
        buffer[index] = static_cast<std::uint8_t>(index + 1);
    }
    RecordingAllocator::reset();

    buffer.resize(4096);

    ASSERT_EQ(RecordingAllocator::deallocation_count, 1u);
    EXPECT_EQ(RecordingAllocator::deallocations[0].elements, 8u);
    EXPECT_TRUE(RecordingAllocator::deallocations[0].was_zeroed);
    for (std::size_t index = 0; index < 8; ++index) {
        EXPECT_EQ(buffer[index], static_cast<std::uint8_t>(index + 1));
    }
    EXPECT_TRUE(std::all_of(buffer.begin() + 8, buffer.end(),
                            [](std::uint8_t value) { return value == 0; }));
}

TEST(SecureBufferTest, ShrinkThenClearUnlocksTheOriginalRange) {
    RecordingPageLocker::lock_succeeds = true;
    LockedBuffer buffer(8192);
    void* const original_ptr = buffer.data();
    RecordingPageLocker::reset();

    buffer.resize(1);
    buffer.clear();

    ASSERT_EQ(RecordingPageLocker::event_count, 1u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, original_ptr);
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 8192u);
}

TEST(SecureBufferTest, ShrinkThenGrowLocksNewRangeBeforeUnlockingOriginalRange) {
    RecordingPageLocker::lock_succeeds = true;
    LockedBuffer buffer(8192);
    void* const original_ptr = buffer.data();
    RecordingPageLocker::reset();

    buffer.resize(1);
    buffer.resize(16384);

    ASSERT_EQ(RecordingPageLocker::event_count, 2u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Lock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, buffer.data());
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 16384u);
    EXPECT_EQ(RecordingPageLocker::events[1].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[1].ptr, original_ptr);
    EXPECT_EQ(RecordingPageLocker::events[1].bytes, 8192u);
    EXPECT_TRUE(RecordingPageLocker::events[1].was_zeroed_at_unlock);

    void* const replacement_ptr = buffer.data();
    buffer.clear();
    ASSERT_EQ(RecordingPageLocker::event_count, 3u);
    EXPECT_EQ(RecordingPageLocker::events[2].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[2].ptr, replacement_ptr);
    EXPECT_EQ(RecordingPageLocker::events[2].bytes, 16384u);
    EXPECT_TRUE(RecordingPageLocker::events[2].was_zeroed_at_unlock);
}

TEST(SecureBufferTest, MultipleShrinksKeepTheOriginalLockRange) {
    RecordingPageLocker::lock_succeeds = true;
    LockedBuffer buffer(8192);
    void* const original_ptr = buffer.data();
    RecordingPageLocker::reset();

    buffer.resize(4097);
    buffer.resize(1);
    buffer.clear();

    ASSERT_EQ(RecordingPageLocker::event_count, 1u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, original_ptr);
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 8192u);
    EXPECT_TRUE(RecordingPageLocker::events[0].was_zeroed_at_unlock);
}

TEST(SecureBufferTest, CopyConstructionLocksAZeroedReplacementBeforeCopying) {
    RecordingPageLocker::lock_succeeds = true;
    LockedBuffer source(8);
    std::fill(source.begin(), source.end(), static_cast<std::uint8_t>(0xA5));
    RecordingPageLocker::reset();

    LockedBuffer copy(source);

    ASSERT_EQ(RecordingPageLocker::event_count, 1u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Lock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, copy.data());
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 8u);
    EXPECT_TRUE(RecordingPageLocker::events[0].was_zeroed_at_lock);
    EXPECT_TRUE(std::equal(source.begin(), source.end(), copy.begin()));
}

TEST(SecureBufferTest, StringConstructionLocksAZeroedReplacementBeforeCopying) {
    RecordingPageLocker::lock_succeeds = true;
    std::string source("secret");
    RecordingPageLocker::reset();

    LockedBuffer buffer(std::move(source));

    ASSERT_EQ(RecordingPageLocker::event_count, 1u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Lock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, buffer.data());
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 6u);
    EXPECT_TRUE(RecordingPageLocker::events[0].was_zeroed_at_lock);
    EXPECT_EQ(buffer.size(), 6u);
    EXPECT_TRUE(source.empty());
}

TEST(SecureBufferTest, CopyAssignmentLocksReplacementBeforeReleasingDestination) {
    RecordingPageLocker::lock_succeeds = true;
    LockedBuffer source(8);
    std::fill(source.begin(), source.end(), static_cast<std::uint8_t>(0xA5));
    LockedBuffer destination(4);
    void* const destination_ptr = destination.data();
    RecordingPageLocker::reset();

    destination = source;

    ASSERT_EQ(RecordingPageLocker::event_count, 2u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Lock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, destination.data());
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 8u);
    EXPECT_TRUE(RecordingPageLocker::events[0].was_zeroed_at_lock);
    EXPECT_EQ(RecordingPageLocker::events[1].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[1].ptr, destination_ptr);
    EXPECT_EQ(RecordingPageLocker::events[1].bytes, 4u);
    EXPECT_TRUE(RecordingPageLocker::events[1].was_zeroed_at_unlock);
    EXPECT_TRUE(std::equal(source.begin(), source.end(), destination.begin()));
}

TEST(SecureBufferTest, AssignLocksReplacementBeforeReleasingDestination) {
    RecordingPageLocker::lock_succeeds = true;
    const std::array<std::uint8_t, 8> source{{1, 2, 3, 4, 5, 6, 7, 8}};
    LockedBuffer destination(4);
    void* const destination_ptr = destination.data();
    RecordingPageLocker::reset();

    destination.assign(source.data(), source.size());

    ASSERT_EQ(RecordingPageLocker::event_count, 2u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Lock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, destination.data());
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 8u);
    EXPECT_TRUE(RecordingPageLocker::events[0].was_zeroed_at_lock);
    EXPECT_EQ(RecordingPageLocker::events[1].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[1].ptr, destination_ptr);
    EXPECT_EQ(RecordingPageLocker::events[1].bytes, 4u);
    EXPECT_TRUE(RecordingPageLocker::events[1].was_zeroed_at_unlock);
    EXPECT_TRUE(std::equal(source.begin(), source.end(), destination.begin()));
}

TEST(SecureBufferTest, MoveConstructionTransfersTheLockedRange) {
    RecordingPageLocker::lock_succeeds = true;
    LockedBuffer source(8);
    void* const source_ptr = source.data();
    RecordingPageLocker::reset();

    LockedBuffer destination(std::move(source));

    EXPECT_EQ(destination.data(), source_ptr);
    EXPECT_TRUE(destination.is_locked());
    EXPECT_FALSE(source.is_locked());
    EXPECT_EQ(RecordingPageLocker::event_count, 0u);
    destination.clear();
    ASSERT_EQ(RecordingPageLocker::event_count, 1u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, source_ptr);
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 8u);
}

TEST(SecureBufferTest, MoveAssignmentTransfersTheLockedRangeForEqualAllocators) {
    RecordingPageLocker::lock_succeeds = true;
    LockedBuffer source(8);
    void* const source_ptr = source.data();
    LockedBuffer destination(4);
    void* const destination_ptr = destination.data();
    RecordingPageLocker::reset();

    destination = std::move(source);

    EXPECT_EQ(destination.data(), source_ptr);
    EXPECT_TRUE(destination.is_locked());
    EXPECT_FALSE(source.is_locked());
    ASSERT_EQ(RecordingPageLocker::event_count, 1u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, destination_ptr);
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 4u);
    destination.clear();
    ASSERT_EQ(RecordingPageLocker::event_count, 2u);
    EXPECT_EQ(RecordingPageLocker::events[1].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[1].ptr, source_ptr);
    EXPECT_EQ(RecordingPageLocker::events[1].bytes, 8u);
}

TEST(SecureBufferTest, MoveAssignmentCopiesSafelyForUnequalAllocators) {
    RecordingPageLocker::lock_succeeds = true;
    StatefulBuffer::vector_type source_storage(8, static_cast<std::uint8_t>(0xA5),
                                                StatefulAllocator<std::uint8_t>(1));
    StatefulBuffer source(std::move(source_storage));
    void* const source_ptr = source.data();
    StatefulBuffer destination(4);
    void* const destination_ptr = destination.data();
    RecordingPageLocker::reset();

    destination = std::move(source);

    ASSERT_EQ(RecordingPageLocker::event_count, 3u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Lock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, destination.data());
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 8u);
    EXPECT_TRUE(RecordingPageLocker::events[0].was_zeroed_at_lock);
    EXPECT_EQ(RecordingPageLocker::events[1].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[1].ptr, destination_ptr);
    EXPECT_EQ(RecordingPageLocker::events[1].bytes, 4u);
    EXPECT_EQ(RecordingPageLocker::events[2].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[2].ptr, source_ptr);
    EXPECT_EQ(RecordingPageLocker::events[2].bytes, 8u);
    EXPECT_TRUE(RecordingPageLocker::events[1].was_zeroed_at_unlock);
    EXPECT_TRUE(RecordingPageLocker::events[2].was_zeroed_at_unlock);
    EXPECT_FALSE(source.is_locked());
    EXPECT_TRUE(std::all_of(destination.begin(), destination.end(),
                            [](std::uint8_t value) { return value == 0xA5; }));
}

TEST(SecureBufferTest, FailedPageLockLeavesTheBufferUsableAndUnlocked) {
    RecordingPageLocker::lock_succeeds = false;
    RecordingPageLocker::reset();

    LockedBuffer buffer(32);

    EXPECT_FALSE(buffer.is_locked());
    ASSERT_EQ(RecordingPageLocker::event_count, 1u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Lock);
    buffer.clear();
    EXPECT_EQ(RecordingPageLocker::event_count, 1u);
    RecordingPageLocker::lock_succeeds = true;
}

TEST(SecureBufferTest, LockRangeUsesByteSizeForWiderElementTypes) {
    RecordingPageLocker::lock_succeeds = true;
    RecordingPageLocker::reset();

    WideBuffer buffer(3);
    void* const buffer_ptr = buffer.data();

    ASSERT_EQ(RecordingPageLocker::event_count, 1u);
    EXPECT_EQ(RecordingPageLocker::events[0].type, PageLockEventType::Lock);
    EXPECT_EQ(RecordingPageLocker::events[0].ptr, buffer_ptr);
    EXPECT_EQ(RecordingPageLocker::events[0].bytes, 3u * sizeof(std::uint32_t));
    EXPECT_TRUE(RecordingPageLocker::events[0].was_zeroed_at_lock);
    buffer.clear();
    ASSERT_EQ(RecordingPageLocker::event_count, 2u);
    EXPECT_EQ(RecordingPageLocker::events[1].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[1].ptr, buffer_ptr);
    EXPECT_EQ(RecordingPageLocker::events[1].bytes, 3u * sizeof(std::uint32_t));
}

TEST(SecureBufferTest, RejectsElementCountsWhoseByteSizeOverflows) {
    hmac_cpp::secure_buffer<std::uint32_t> buffer;

    EXPECT_THROW(buffer.resize(std::numeric_limits<std::size_t>::max()), std::length_error);
}

TEST(SecureBufferTest, StringAssignWipesTheSourceWhenReplacementAllocationFails) {
    ThrowingAllocator::fail_allocations = false;
    ThrowingBuffer destination(4);
    destination[0] = 0x5A;
    const void* const destination_ptr = destination.data();
    std::string source(128, 's');
    const char* const source_data = source.data();
    const std::size_t source_size = source.size();
    ThrowingAllocator::fail_allocations = true;

    EXPECT_THROW(destination.assign(std::move(source)), std::bad_alloc);

    ThrowingAllocator::fail_allocations = false;
    EXPECT_TRUE(source.empty());
    EXPECT_TRUE(std::all_of(source_data, source_data + source_size,
                            [](char value) { return value == 0; }));
    EXPECT_EQ(destination.data(), destination_ptr);
    EXPECT_EQ(destination.size(), 4u);
    EXPECT_EQ(destination[0], 0x5A);
}

TEST(PageLockRegistryTest, SharedPageRemainsLockedUntilEveryOwnerReleasesIt) {
    RegistryPageLocker::reset();
    hmac_cpp::detail::page_lock_registry<RegistryPageLocker> registry(4096);
    void* const first = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1001));
    void* const second = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1008));

    ASSERT_TRUE(registry.lock(first, 8));
    ASSERT_TRUE(registry.lock(second, 8));
    ASSERT_TRUE(registry.unlock(first, 8));

    ASSERT_EQ(RegistryPageLocker::event_count, 1u);
    EXPECT_EQ(RegistryPageLocker::events[0].type, RegistryEventType::Lock);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(RegistryPageLocker::events[0].page), 0x1000u);

    ASSERT_TRUE(registry.unlock(second, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 2u);
    EXPECT_EQ(RegistryPageLocker::events[1].type, RegistryEventType::Unlock);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(RegistryPageLocker::events[1].page), 0x1000u);
}

TEST(PageLockRegistryTest, RollsBackPagesLockedBeforeAPartialFailure) {
    RegistryPageLocker::reset();
    RegistryPageLocker::failing_page = 0x2000;
    hmac_cpp::detail::page_lock_registry<RegistryPageLocker> registry(4096);
    void* const range = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1ff8));

    EXPECT_FALSE(registry.lock(range, 16));
    ASSERT_EQ(RegistryPageLocker::event_count, 3u);
    EXPECT_EQ(RegistryPageLocker::events[0].type, RegistryEventType::Lock);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(RegistryPageLocker::events[0].page), 0x1000u);
    EXPECT_EQ(RegistryPageLocker::events[1].type, RegistryEventType::Lock);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(RegistryPageLocker::events[1].page), 0x2000u);
    EXPECT_EQ(RegistryPageLocker::events[2].type, RegistryEventType::Unlock);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(RegistryPageLocker::events[2].page), 0x1000u);
    EXPECT_FALSE(registry.unlock(range, 16));
}

TEST(PageLockRegistryTest, PageStateInsertionFailureReturnsFalseAndClearsPreparedEntries) {
    using PageState = hmac_cpp::detail::page_lock_page_state;
    using Allocator = ThrowingPageStateAllocator<std::pair<const std::uintptr_t, PageState>>;
    using Registry = hmac_cpp::detail::page_lock_registry<RegistryPageLocker, std::mutex, Allocator>;

    RegistryPageLocker::reset();
    PageStateAllocationControl::successful_allocations_before_failure = 1;
    Registry registry(4096);
    void* const range = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1000));

    EXPECT_FALSE(registry.lock(range, 8193));
    EXPECT_EQ(RegistryPageLocker::event_count, 0u);

    // If prepared entries remained, this range would reuse the first one and
    // reach the OS locker despite allocations being disabled.
    PageStateAllocationControl::successful_allocations_before_failure = 0;
    EXPECT_FALSE(registry.lock(range, 8));
    EXPECT_EQ(RegistryPageLocker::event_count, 0u);

    PageStateAllocationControl::successful_allocations_before_failure = -1;
    EXPECT_TRUE(registry.lock(range, 8));
    EXPECT_TRUE(registry.unlock(range, 8));
    EXPECT_EQ(RegistryPageLocker::event_count, 2u);
}

TEST(PageLockRegistryTest, UnlockFailureDoesNotCreateAPhantomOwner) {
    RegistryPageLocker::reset();
    hmac_cpp::detail::page_lock_registry<RegistryPageLocker> registry(4096);
    void* const page = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1001));

    ASSERT_TRUE(registry.lock(page, 8));
    RegistryPageLocker::failing_unlock_page = 0x1000;
    EXPECT_FALSE(registry.unlock(page, 8));
    EXPECT_FALSE(registry.unlock(page, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 2u);

    RegistryPageLocker::failing_unlock_page = 0;
    ASSERT_TRUE(registry.lock(page, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 2u);
    EXPECT_TRUE(registry.unlock(page, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 3u);
    EXPECT_EQ(RegistryPageLocker::events[2].type, RegistryEventType::Unlock);
}

TEST(PageLockRegistryTest, RetryAfterFailedMixedRangeUnlockPreservesOverlappingOwner) {
    RegistryPageLocker::reset();
    hmac_cpp::detail::page_lock_registry<RegistryPageLocker> registry(4096);
    void* const mixed_range = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1000));
    void* const overlapping_page = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1004));
    void* const second_page = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x2000));

    ASSERT_TRUE(registry.lock(mixed_range, 4097));
    ASSERT_TRUE(registry.lock(overlapping_page, 8));
    RegistryPageLocker::failing_unlock_page = 0x2000;
    EXPECT_FALSE(registry.unlock(mixed_range, 4097));
    ASSERT_EQ(RegistryPageLocker::event_count, 3u);

    RegistryPageLocker::failing_unlock_page = 0;
    EXPECT_FALSE(registry.unlock(mixed_range, 4097));
    ASSERT_EQ(RegistryPageLocker::event_count, 3u);
    EXPECT_TRUE(registry.unlock(overlapping_page, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 4u);
    EXPECT_EQ(RegistryPageLocker::events[3].type, RegistryEventType::Unlock);
    EXPECT_EQ(RegistryPageLocker::events[3].page, mixed_range);

    ASSERT_TRUE(registry.lock(second_page, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 4u);
    EXPECT_TRUE(registry.unlock(second_page, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 5u);
}

TEST(PageLockRegistryTest, RollbackUnlockFailureCanBeReleasedByAFutureOwner) {
    RegistryPageLocker::reset();
    hmac_cpp::detail::page_lock_registry<RegistryPageLocker> registry(4096);
    void* const mixed_range = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1000));
    void* const first_page = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1008));

    RegistryPageLocker::failing_page = 0x2000;
    RegistryPageLocker::failing_unlock_page = 0x1000;
    EXPECT_FALSE(registry.lock(mixed_range, 4097));
    ASSERT_EQ(RegistryPageLocker::event_count, 3u);

    RegistryPageLocker::failing_page = 0;
    RegistryPageLocker::failing_unlock_page = 0;
    EXPECT_FALSE(registry.unlock(mixed_range, 4097));
    ASSERT_EQ(RegistryPageLocker::event_count, 3u);
    ASSERT_TRUE(registry.lock(first_page, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 3u);
    EXPECT_TRUE(registry.unlock(first_page, 8));
    ASSERT_EQ(RegistryPageLocker::event_count, 4u);
    EXPECT_EQ(RegistryPageLocker::events[3].type, RegistryEventType::Unlock);
    EXPECT_EQ(RegistryPageLocker::events[3].page, reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1000)));
}

TEST(PageLockRegistryTest, MutexFailureReturnsFalseInsteadOfTerminating) {
    RegistryPageLocker::reset();
    hmac_cpp::detail::page_lock_registry<RegistryPageLocker, ThrowingMutex> registry(4096);
    void* const page = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x1001));

    EXPECT_FALSE(registry.lock(page, 8));
    EXPECT_FALSE(registry.unlock(page, 8));
    EXPECT_EQ(RegistryPageLocker::event_count, 0u);
}

} // namespace
