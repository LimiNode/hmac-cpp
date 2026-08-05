#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>

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
};

struct RecordingPageLocker {
    static bool lock(void* ptr, std::size_t bytes) noexcept {
        events[event_count++] = {
            PageLockEventType::Lock,
            ptr,
            bytes,
            std::all_of(static_cast<const std::uint8_t*>(ptr),
                        static_cast<const std::uint8_t*>(ptr) + bytes,
                        [](std::uint8_t value) { return value == 0; })
        };
        return lock_succeeds;
    }

    static bool unlock(void* ptr, std::size_t bytes) noexcept {
        events[event_count++] = {PageLockEventType::Unlock, ptr, bytes, false};
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

    void* const replacement_ptr = buffer.data();
    buffer.clear();
    ASSERT_EQ(RecordingPageLocker::event_count, 3u);
    EXPECT_EQ(RecordingPageLocker::events[2].type, PageLockEventType::Unlock);
    EXPECT_EQ(RecordingPageLocker::events[2].ptr, replacement_ptr);
    EXPECT_EQ(RecordingPageLocker::events[2].bytes, 16384u);
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

} // namespace
