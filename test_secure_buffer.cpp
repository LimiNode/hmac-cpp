#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

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

    static std::array<DeallocationRecord, 16> deallocations;
    static std::size_t deallocation_count;
};

bool operator==(const RecordingAllocator&, const RecordingAllocator&) noexcept { return true; }
bool operator!=(const RecordingAllocator&, const RecordingAllocator&) noexcept { return false; }

std::array<DeallocationRecord, 16> RecordingAllocator::deallocations{};
std::size_t RecordingAllocator::deallocation_count{};

enum class PageLockEventType { Lock, Unlock };

struct PageLockEvent {
    PageLockEventType type{};
    void* ptr{};
    std::size_t bytes{};
};

struct RecordingPageLocker {
    static bool lock(void* ptr, std::size_t bytes) noexcept {
        events[event_count++] = {PageLockEventType::Lock, ptr, bytes};
        return true;
    }

    static bool unlock(void* ptr, std::size_t bytes) noexcept {
        events[event_count++] = {PageLockEventType::Unlock, ptr, bytes};
        return true;
    }

    static void reset() noexcept { event_count = 0; }

    static std::array<PageLockEvent, 16> events;
    static std::size_t event_count;
};

std::array<PageLockEvent, 16> RecordingPageLocker::events{};
std::size_t RecordingPageLocker::event_count{};

using UnlockedBuffer = hmac_cpp::secure_buffer<std::uint8_t, false, RecordingAllocator>;
using LockedBuffer = hmac_cpp::secure_buffer<std::uint8_t,
                                              true,
                                              RecordingAllocator,
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

} // namespace
