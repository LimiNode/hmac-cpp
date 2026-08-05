#include <gtest/gtest.h>
#include <string>
#include <stdexcept>
#include <vector>
#include <limits>
#include <cerrno>
#include <random>
#include <array>
#include <algorithm>
#include <openssl/evp.h>

#include "hmac_cpp/hmac.hpp"
#include "hmac_cpp/hmac_utils.hpp"
#include "hmac_cpp/encoding.hpp"
#include "hmac_cpp/secret_string.hpp"

static std::time_t mock_time_value = 0;
static int mock_errno_value = 0;
extern "C" std::time_t time(std::time_t* t) {
    if (t) *t = mock_time_value;
    errno = mock_errno_value;
    return mock_time_value;
}

static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byte = hex.substr(i, 2);
        out.push_back(static_cast<uint8_t>(std::stoi(byte, nullptr, 16)));
    }
    return out;
}

TEST(HashTest, SHA1) {
    EXPECT_EQ(hmac_hash::sha1("grape"),
              "bc8a2f8cdedb005b5c787692853709b060db75ff");
}

TEST(HashTest, SHA256) {
    EXPECT_EQ(hmac_hash::sha256("grape"),
              "0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496");
}

TEST(HashTest, SHA512) {
    EXPECT_EQ(hmac_hash::sha512("grape"),
              "9375d1abdb644a01955bccad12e2f5c2bd8a3e226187e548d99c559a99461453b980123746753d07c169c22a5d9cc75cb158f0e8d8c0e713559775b5e1391fc4");
}

TEST(HashTest, SHA512LargeInput) {
    hmac_hash::SHA512 ctx;
    ctx.init();
    std::vector<uint8_t> chunk(1024 * 1024, 'a');
    for (size_t i = 0; i < 4096; ++i) {
        ctx.update(chunk.data(), chunk.size());
    }
    uint8_t tail = 'b';
    ctx.update(&tail, 1);

    uint8_t digest[hmac_hash::SHA512::DIGEST_SIZE];
    ctx.finish(digest);
    std::string result(reinterpret_cast<char*>(digest), hmac_hash::SHA512::DIGEST_SIZE);
    EXPECT_EQ(hmac::to_hex(result),
              "596d71e02b4eca81f668215d3e9b9e5a143a9c3d8d1981608e0811b20e290961ec2a7e7ecd0e275366cf10aa5f7ab1e052b868c5fa57b6d2bd6e75477b2ecea7");
}

TEST(HashTest, InvalidTypeThrowsString) {
    auto invalid = static_cast<hmac::TypeHash>(999);
    EXPECT_THROW(hmac::get_hash("grape", invalid), std::invalid_argument);
}

TEST(HashTest, InvalidTypeThrowsBuffer) {
    auto invalid = static_cast<hmac::TypeHash>(999);
    const char data[] = "grape";
    EXPECT_THROW(hmac::get_hash(data, sizeof(data) - 1, invalid), std::invalid_argument);
}

TEST(UtilsTest, ToHex) {
    EXPECT_EQ(hmac::to_hex("012345"), "303132333435");
}

TEST(UtilsTest, ConstantTimeEqualsMatch) {
    EXPECT_TRUE(hmac::constant_time_equals("alpha", "alpha"));
}

TEST(UtilsTest, ConstantTimeEqualsMismatch) {
    EXPECT_FALSE(hmac::constant_time_equals("alpha", "beta"));
    EXPECT_FALSE(hmac::constant_time_equals("alpha", "alphabet"));
}

TEST(UtilsTest, ConstantTimeEqualsLengthMultiples256) {
    std::string base(256, 'a');
    std::string plus256 = base + std::string(256, '\0');
    std::string plus512 = base + std::string(512, '\0');
    EXPECT_FALSE(hmac::constant_time_equals(base, plus256));
    EXPECT_FALSE(hmac::constant_time_equals(base, plus512));
}

TEST(UtilsTest, ConstantTimeEqualsVector) {
    std::vector<uint8_t> a = {1, 2, 3};
    std::vector<uint8_t> b = {1, 2, 3};
    EXPECT_TRUE(hmac::constant_time_equals(a, b));
    b[2] = 4;
    EXPECT_FALSE(hmac::constant_time_equals(a, b));
}

TEST(HMACTest, SHA256) {
    const std::string key = "12345";
    const std::string input = "grape";
    EXPECT_EQ(hmac::get_hmac(key, input, hmac::TypeHash::SHA256, true),
              "7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca");
}

TEST(HMACTest, SHA512) {
    const std::string key = "12345";
    const std::string input = "grape";
    EXPECT_EQ(hmac::get_hmac(key, input, hmac::TypeHash::SHA512, true),
              "c54ddf9647a949d0df925a1c1f8ba1c9d721a671c396fde1062a71f9f7ffae5dc10f6be15be63bb0363d051365e23f890368c54828497b9aef2eb2fc65b633e6");
}

TEST(HMACTest, SHA512Uppercase) {
    const std::string key = "12345";
    const std::string input = "grape";
    EXPECT_EQ(hmac::get_hmac(key, input, hmac::TypeHash::SHA512, true, true),
              "C54DDF9647A949D0DF925A1C1F8BA1C9D721A671C396FDE1062A71F9F7FFAE5DC10F6BE15BE63BB0363D051365E23F890368C54828497B9AEF2EB2FC65B633E6");
}

TEST(HMACTest, NullPointersThrow) {
    const char* msg = "abc";
    EXPECT_THROW(hmac::get_hmac(nullptr, 1, msg, 3, hmac::TypeHash::SHA256), std::invalid_argument);
    const char* key = "key";
    EXPECT_THROW(hmac::get_hmac(key, 3, nullptr, 1, hmac::TypeHash::SHA256), std::invalid_argument);
}

TEST(HMACTest, InvalidTypeThrows) {
    const char* key = "key";
    const char* msg = "abc";
    auto invalid = static_cast<hmac::TypeHash>(999);
    EXPECT_THROW(hmac::get_hmac(key, 3, msg, 3, invalid), std::invalid_argument);
}

TEST(HMACTest, MsgLenOverflowThrows) {
    const char key[] = "key";
    const char msg[] = "a";
    size_t huge_len = std::numeric_limits<size_t>::max() -
                       hmac_hash::SHA256::SHA224_256_BLOCK_SIZE + 1;
    EXPECT_THROW(hmac::get_hmac(key, sizeof(key) - 1, msg, huge_len,
                                hmac::TypeHash::SHA256), std::overflow_error);
}

TEST(HMACTest, InvalidTypeThrowsString) {
    const std::string key = "key";
    const std::string msg = "abc";
    auto invalid = static_cast<hmac::TypeHash>(999);
    EXPECT_THROW(hmac::get_hmac(key, msg, invalid), std::invalid_argument);
}

TEST(HMACTest, RFC2202SHA1Vectors) {
    struct Vector {
        std::string key;
        std::string data;
        std::string sha1;
    };
    std::vector<Vector> vectors;
    vectors.push_back({std::string(20, '\x0b'), "Hi There",
                       "b617318655057264e28bc0b6fb378c8ef146be00"});
    vectors.push_back({"Jefe", "what do ya want for nothing?",
                       "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"});
    vectors.push_back({std::string(20, '\xaa'), std::string(50, '\xdd'),
                       "125d7342b9ac11cd91a39af48aa17b4f63f175d3"});
    {
        std::string key;
        for (int i = 1; i <= 25; ++i) key.push_back(static_cast<char>(i));
        vectors.push_back({key, std::string(50, '\xcd'),
                           "4c9007f4026250c6bc8414f9bf50c86c2d7235da"});
    }
    vectors.push_back({std::string(20, '\x0c'), "Test With Truncation",
                       "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"});
    vectors.push_back({std::string(80, '\xaa'),
                       "Test Using Larger Than Block-Size Key - Hash Key First",
                       "aa4ae5e15272d00e95705637ce8a3b55ed402112"});
    vectors.push_back({std::string(80, '\xaa'),
                       "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                       "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"});

    for (size_t i = 0; i < vectors.size(); ++i) {
        EXPECT_EQ(hmac::get_hmac(vectors[i].key, vectors[i].data,
                                 hmac::TypeHash::SHA1, true),
                  vectors[i].sha1)
            << "Case " << i + 1 << " SHA1 mismatch";
    }
}

TEST(HMACTest, RFC4231Vectors) {
    struct Vector {
        std::string key_hex;
        std::string data_hex;
        std::string sha256;
        std::string sha512;
        size_t truncate_to;
    };

    auto repeat = [](const std::string& pattern, size_t count) {
        std::string s;
        s.reserve(pattern.size() * count);
        for (size_t i = 0; i < count; ++i) s += pattern;
        return s;
    };

    std::vector<Vector> vectors = {
        { repeat("0b", 20), "4869205468657265",
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
          "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
          0 },
        { "4a656665",
          "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
          0 },
        { repeat("aa", 20), repeat("dd", 50),
          "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
          "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
          0 },
        { "0102030405060708090a0b0c0d0e0f10111213141516171819", repeat("cd", 50),
          "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
          "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
          0 },
        { repeat("0c", 20), "546573742057697468205472756e636174696f6e",
          "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
          "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b",
          16 },
        { repeat("aa", 131), "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
          "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
          0 },
        { repeat("aa", 131),
          "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f2062652068617368656420746f67657468657220616e64207468652064617461206e6565647320746f2062652068617368656420746f6765746865722e",
          "aa2c6460ff60440a71a9bbb5c07ce5d6e6bee38e2921ed125b55696163532437",
          "61466c9d01731984d7c3e9fa4e03beb5a793835c147b6350642a6e9a921c312b844925b7434e5e075c9c6643d48fd0bda27a9d1a7d0f0287fa0839aa6959bbe2",
          0 }
    };

    for (size_t i = 0; i < vectors.size(); ++i) {
        auto key = from_hex(vectors[i].key_hex);
        auto data = from_hex(vectors[i].data_hex);
        auto h256 = hmac::get_hmac(key, data, hmac::TypeHash::SHA256);
        auto h512 = hmac::get_hmac(key, data, hmac::TypeHash::SHA512);
        std::string h256_hex = hmac::to_hex(std::string(h256.begin(), h256.end()));
        std::string h512_hex = hmac::to_hex(std::string(h512.begin(), h512.end()));
        EXPECT_EQ(h256_hex, vectors[i].sha256) << "Case " << i + 1 << " SHA-256 mismatch";
        EXPECT_EQ(h512_hex, vectors[i].sha512) << "Case " << i + 1 << " SHA-512 mismatch";
        if (vectors[i].truncate_to) {
            EXPECT_EQ(h256_hex.substr(0, vectors[i].truncate_to * 2),
                      vectors[i].sha256.substr(0, vectors[i].truncate_to * 2))
                << "Case " << i + 1 << " SHA-256 trunc mismatch";
            EXPECT_EQ(h512_hex.substr(0, vectors[i].truncate_to * 2),
                      vectors[i].sha512.substr(0, vectors[i].truncate_to * 2))
                << "Case " << i + 1 << " SHA-512 trunc mismatch";
        }
    }
}

TEST(HMACTest, RFC2202Vectors) {
    struct Vector {
        std::string key_hex;
        std::string data_hex;
        std::string sha1;
    };
    // HMAC-SHA1 test cases from RFC 2202
    auto repeat = [](const std::string& pattern, size_t count) {
        std::string s;
        s.reserve(pattern.size() * count);
        for (size_t i = 0; i < count; ++i) s += pattern;
        return s;
    };

    std::vector<Vector> vectors = {
        { repeat("0b", 20), "4869205468657265",
          "b617318655057264e28bc0b6fb378c8ef146be00" },
        { "4a656665",
          "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
          "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" },
        { repeat("aa", 20), repeat("dd", 50),
          "125d7342b9ac11cd91a39af48aa17b4f63f175d3" },
        { "0102030405060708090a0b0c0d0e0f10111213141516171819", repeat("cd", 50),
          "4c9007f4026250c6bc8414f9bf50c86c2d7235da" },
        { repeat("0c", 20), "546573742057697468205472756e636174696f6e",
          "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04" },
        { repeat("aa", 80), "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
          "aa4ae5e15272d00e95705637ce8a3b55ed402112" },
        { repeat("aa", 80), "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461",
          "e8e99d0f45237d786d6bbaa7965c7808bbff1a91" }
    };

    for (size_t i = 0; i < vectors.size(); ++i) {
        auto key = from_hex(vectors[i].key_hex);
        auto data = from_hex(vectors[i].data_hex);
        auto h = hmac::get_hmac(key, data, hmac::TypeHash::SHA1);
        std::string hex = hmac::to_hex(std::string(h.begin(), h.end()));
        EXPECT_EQ(hex, vectors[i].sha1) << "Case " << i + 1 << " SHA1 mismatch";
    }
}

TEST(HOTPTest, ShortDigestThrows) {
    std::vector<uint8_t> short_digest = {0x00, 0x01, 0x02};
    EXPECT_THROW(hmac::detail::hotp_from_digest(short_digest, 6), std::runtime_error);
}

TEST(TOTPTest, AtTime) {
    const std::string totp_key = "12345678901234567890";
    uint64_t test_time = 1234567890;
    int code = hmac::get_totp_code_at(totp_key, test_time, 30, 8, hmac::TypeHash::SHA1);
    EXPECT_EQ(code, 89005924);
}

TEST(TokenTest, InvalidInterval) {
    const std::string key = "12345";
    std::string token = hmac::generate_time_token(key, 60);
    EXPECT_THROW(hmac::generate_time_token(key, 0), std::invalid_argument);
    EXPECT_THROW(hmac::is_token_valid(token, key, 0), std::invalid_argument);
}

TEST(TokenBoundaryTest, MaxTime) {
    const std::string key = "12345";
    const int interval = 30;
    mock_time_value = std::numeric_limits<std::time_t>::max();
    std::string token = hmac::generate_time_token(key, interval);
    EXPECT_TRUE(hmac::is_token_valid(token, key, interval));
    mock_time_value = std::numeric_limits<std::time_t>::max() - interval;
    std::string token_prev = hmac::generate_time_token(key, interval);
    mock_time_value = std::numeric_limits<std::time_t>::max();
    EXPECT_TRUE(hmac::is_token_valid(token_prev, key, interval));
}

TEST(TokenBoundaryTest, MinTime) {
    const std::string key = "12345";
    const int interval = 30;
    mock_time_value = std::numeric_limits<std::time_t>::min();
    std::string token = hmac::generate_time_token(key, interval);
    EXPECT_TRUE(hmac::is_token_valid(token, key, interval));
    mock_time_value = std::numeric_limits<std::time_t>::min() + interval;
    std::string token_next = hmac::generate_time_token(key, interval);
    mock_time_value = std::numeric_limits<std::time_t>::min();
    EXPECT_TRUE(hmac::is_token_valid(token_next, key, interval));
}

TEST(TokenBoundaryFingerprintTest, MaxTime) {
    const std::string key = "12345";
    const std::string fingerprint = "fp";
    const int interval = 30;
    mock_time_value = std::numeric_limits<std::time_t>::max();
    std::string token = hmac::generate_time_token(key, fingerprint, interval);
    EXPECT_TRUE(hmac::is_token_valid(token, key, fingerprint, interval));
    mock_time_value = std::numeric_limits<std::time_t>::max() - interval;
    std::string token_prev = hmac::generate_time_token(key, fingerprint, interval);
    mock_time_value = std::numeric_limits<std::time_t>::max();
    EXPECT_TRUE(hmac::is_token_valid(token_prev, key, fingerprint, interval));
}

TEST(TokenBoundaryFingerprintTest, MinTime) {
    const std::string key = "12345";
    const std::string fingerprint = "fp";
    const int interval = 30;
    mock_time_value = std::numeric_limits<std::time_t>::min();
    std::string token = hmac::generate_time_token(key, fingerprint, interval);
    EXPECT_TRUE(hmac::is_token_valid(token, key, fingerprint, interval));
    mock_time_value = std::numeric_limits<std::time_t>::min() + interval;
    std::string token_next = hmac::generate_time_token(key, fingerprint, interval);
    mock_time_value = std::numeric_limits<std::time_t>::min();
    EXPECT_TRUE(hmac::is_token_valid(token_next, key, fingerprint, interval));
}

TEST(PBKDF2Validation, EmptySaltThrows) {
    EXPECT_THROW(hmac::pbkdf2("password", "", 2, 20, hmac::Pbkdf2Hash::Sha1), std::invalid_argument);
}

TEST(PBKDF2Validation, ZeroIterationsThrows) {
    std::string salt(16, 'a');
    EXPECT_THROW(hmac::pbkdf2("password", salt, 0, 32, hmac::Pbkdf2Hash::Sha256), std::invalid_argument);
}

TEST(PBKDF2Validation, TooLargeDkLenThrows) {
    std::string salt(16, 'a');
    size_t too_large = (static_cast<uint64_t>(1) << 32) * 20;
    EXPECT_THROW(hmac::pbkdf2("password", salt, 1, too_large, hmac::Pbkdf2Hash::Sha1), std::invalid_argument);
}

TEST(PBKDF2Rfc6070, Sha1Iter1) {
    auto dk = hmac::pbkdf2("password", "salt", 1, 20, hmac::Pbkdf2Hash::Sha1);
    std::string hex = hmac::to_hex(std::string(dk.begin(), dk.end()));
    EXPECT_EQ(hex, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
}

TEST(PBKDF2Rfc6070, Sha1Iter2) {
    auto dk = hmac::pbkdf2("password", "salt", 2, 20, hmac::Pbkdf2Hash::Sha1);
    std::string hex = hmac::to_hex(std::string(dk.begin(), dk.end()));
    EXPECT_EQ(hex, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
}

TEST(PBKDF2Rfc6070, Sha1Iter4096) {
    auto dk = hmac::pbkdf2("password", "salt", 4096, 20, hmac::Pbkdf2Hash::Sha1);
    std::string hex = hmac::to_hex(std::string(dk.begin(), dk.end()));
    EXPECT_EQ(hex, "4b007901b765489abead49d926f721d065a429c1");
}

TEST(PBKDF2Rfc6070, Sha1LongPassword) {
    auto dk = hmac::pbkdf2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, hmac::Pbkdf2Hash::Sha1);
    std::string hex = hmac::to_hex(std::string(dk.begin(), dk.end()));
    EXPECT_EQ(hex, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
}

TEST(PBKDF2Rfc6070, Sha1WithNull) {
    std::string password("pass\0word", 9);
    std::string salt("sa\0lt", 5);
    auto dk = hmac::pbkdf2(password, salt, 4096, 16, hmac::Pbkdf2Hash::Sha1);
    std::string hex = hmac::to_hex(std::string(dk.begin(), dk.end()));
    EXPECT_EQ(hex, "56fa6aa75548099dcc37d7f03425e0c3");
}

TEST(PBKDF2Unicode, Sha1) {
    std::string password = u8"пароль";
    std::string salt = u8"соль";
    auto dk = hmac::pbkdf2(password, salt, 4096, 20, hmac::Pbkdf2Hash::Sha1);
    std::vector<uint8_t> ref(20);
    ASSERT_TRUE(PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                                  reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
                                  4096, EVP_sha1(), ref.size(), ref.data()));
    EXPECT_TRUE(hmac::constant_time_equals(dk, ref));
}

TEST(PBKDF2Validation, IterationsLimit) {
    std::string salt(16, 'a');
    uint32_t limit = hmac::MAX_PBKDF2_ITERATIONS;
    EXPECT_NO_THROW(hmac::pbkdf2("password", salt, limit - 1, 32, hmac::Pbkdf2Hash::Sha256));
    EXPECT_THROW(hmac::pbkdf2("password", salt, limit + 1, 32, hmac::Pbkdf2Hash::Sha256), std::invalid_argument);
}

TEST(PBKDF2Test, SHA256WithValidSalt) {
    auto salt = from_hex("000102030405060708090a0b0c0d0e0f");
    std::string salt_str(salt.begin(), salt.end());
    auto dk = hmac::pbkdf2(std::string("password"), salt_str, 2, 32, hmac::Pbkdf2Hash::Sha256);
    std::vector<uint8_t> ref(32);
    ASSERT_TRUE(PKCS5_PBKDF2_HMAC("password", 8, salt.data(), salt.size(), 2, EVP_sha256(), ref.size(), ref.data()));
    EXPECT_TRUE(hmac::constant_time_equals(dk, ref));
}

TEST(PBKDF2ResultTest, ComputesFromStoredParams) {
    auto salt = from_hex("000102030405060708090a0b0c0d0e0f");
    std::string salt_str(salt.begin(), salt.end());
    auto dk = hmac::pbkdf2(std::string("password"), salt_str, 2, 32, hmac::Pbkdf2Hash::Sha256);
    hmac::Pbkdf2Result stored{salt, 2, dk};
    auto out = hmac::pbkdf2(std::string("password"), stored);
    EXPECT_TRUE(hmac::constant_time_equals(out.key, stored.key));
}

TEST(PBKDF2BufferApiTest, SHA256ArrayOutput) {
    auto salt = from_hex("000102030405060708090a0b0c0d0e0f");
    std::string salt_str(salt.begin(), salt.end());
    std::array<uint8_t,32> out{};
    ASSERT_TRUE(hmac::pbkdf2_hmac_sha256(std::string("password"), salt_str, 2, out));
    std::vector<uint8_t> ref(32);
    ASSERT_TRUE(PKCS5_PBKDF2_HMAC("password", 8, salt.data(), salt.size(), 2, EVP_sha256(), ref.size(), ref.data()));
    EXPECT_TRUE(std::equal(out.begin(), out.end(), ref.begin()));
}

TEST(PBKDF2BufferApiTest, GenericArrayOutput) {
    auto salt = from_hex("000102030405060708090a0b0c0d0e0f");
    std::string salt_str(salt.begin(), salt.end());
    std::array<uint8_t,32> out{};
    ASSERT_TRUE(hmac::pbkdf2(hmac::Pbkdf2Hash::Sha256,
                             std::string("password"), salt_str, 2, out));
    std::vector<uint8_t> ref(32);
    ASSERT_TRUE(PKCS5_PBKDF2_HMAC("password", 8, salt.data(), salt.size(), 2, EVP_sha256(), ref.size(), ref.data()));
    EXPECT_TRUE(std::equal(out.begin(), out.end(), ref.begin()));
}

TEST(PBKDF2BufferApiTest, IterationsLimit) {
    std::string salt(16, 'a');
    std::array<uint8_t,32> out{};
    uint32_t limit = hmac::MAX_PBKDF2_ITERATIONS;
    EXPECT_TRUE(hmac::pbkdf2_hmac_sha256(std::string("password"), salt, limit - 1, out));
    EXPECT_FALSE(hmac::pbkdf2_hmac_sha256(std::string("password"), salt, limit + 1, out));
}

// SHA512 vector from BoringSSL pbkdf_test.cc
TEST(PBKDF2Test, BoringSSL_SHA512) {
    auto dk = hmac::pbkdf2("passwordPASSWORDpassword",
                           "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                           4096, 64, hmac::Pbkdf2Hash::Sha512);
    std::string hex = hmac::to_hex(std::string(dk.begin(), dk.end()));
    EXPECT_EQ(hex,
              "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8");
}

TEST(PBKDF2Test, OpenSSLRandom) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto prf : {hmac::Pbkdf2Hash::Sha1, hmac::Pbkdf2Hash::Sha256, hmac::Pbkdf2Hash::Sha512}) {
        std::vector<uint8_t> pwd(16), salt(16);
        for (int i = 0; i < 2; ++i) {
            for (auto &x : pwd) x = static_cast<uint8_t>(dist(gen));
            for (auto &x : salt) x = static_cast<uint8_t>(dist(gen));
            size_t dk_len = (prf == hmac::Pbkdf2Hash::Sha1) ? 20 : 32;
            auto ours = hmac::pbkdf2(pwd, salt, 1000, dk_len, prf);
            std::vector<uint8_t> ref(dk_len);
            const EVP_MD* md = nullptr;
            switch (prf) {
                case hmac::Pbkdf2Hash::Sha1: md = EVP_sha1(); break;
                case hmac::Pbkdf2Hash::Sha256: md = EVP_sha256(); break;
                case hmac::Pbkdf2Hash::Sha512: md = EVP_sha512(); break;
            }
            ASSERT_TRUE(PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(pwd.data()), pwd.size(),
                                          salt.data(), salt.size(), 1000, md, dk_len, ref.data()));
            EXPECT_TRUE(hmac::constant_time_equals(ours, ref));
        }
    }
}

TEST(HKDFTest, RFC5869Case1) {
    std::vector<uint8_t> ikm(22, 0x0b);
    auto salt = from_hex("000102030405060708090a0b0c");
    auto info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    auto prk = hmac::hkdf_extract_sha256(ikm, salt);
    std::string prk_hex = hmac::to_hex(std::string(prk.begin(), prk.end()));
    EXPECT_EQ(prk_hex, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    auto okm = hmac::hkdf_expand_sha256(prk, info, 42);
    std::string okm_hex = hmac::to_hex(std::string(okm.begin(), okm.end()));
    EXPECT_EQ(okm_hex,
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

TEST(PBKDF2Test, WithPepper) {
    std::string password = "secret";
    std::string pepper = "server";
    std::vector<uint8_t> salt_vec(16, 0x03);
    std::string salt(salt_vec.begin(), salt_vec.end());
    auto dk1 = hmac::pbkdf2_with_pepper(password, salt, pepper, 1000, 32);
    auto inner = hmac::get_hmac(pepper, password, hmac::TypeHash::SHA256, false);
    std::vector<uint8_t> inner_vec(inner.begin(), inner.end());
    auto dk2 = hmac::pbkdf2(inner_vec, salt_vec, 1000, 32, hmac::Pbkdf2Hash::Sha256);
    EXPECT_TRUE(hmac::constant_time_equals(dk1, dk2));
}

TEST(TimeErrorTest, MinusOneNoErrno) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = 0;
    std::string token;
    EXPECT_NO_THROW(token = hmac::generate_time_token(key));
    EXPECT_EQ(token, hmac::get_hmac(key, "0", hmac::TypeHash::SHA256));
    mock_time_value = 0;
    mock_errno_value = 0;
}

TEST(TimeErrorTest, MinusOneWithErrno) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = EINVAL;
    EXPECT_THROW(hmac::generate_time_token(key), std::runtime_error);
    mock_errno_value = 0;
    mock_time_value = 0;
}

TEST(TotpTimeErrorTest, NegativeTimeThrows) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = 0;
    EXPECT_THROW(hmac::get_totp_code(key), std::runtime_error);
    mock_time_value = 0;
    mock_errno_value = 0;
}

TEST(TotpTimeErrorTest, NegativeTimeThrowsErrno) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = EINVAL;
    EXPECT_THROW(hmac::get_totp_code(key), std::runtime_error);
    mock_errno_value = 0;
    mock_time_value = 0;
}

TEST(TotpTimeErrorTest, ValidityNegativeTimeThrows) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = 0;
    EXPECT_THROW(
        hmac::is_totp_token_valid(0, key.data(), key.size(), 30, 6, hmac::TypeHash::SHA1),
        std::runtime_error);
    mock_time_value = 0;
    mock_errno_value = 0;
}

TEST(EncodingTest, Base64Vectors) {
    std::vector<std::pair<std::string,std::string>> cases = {
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"}
    };
    for (auto& c : cases) {
        std::vector<uint8_t> bin(c.first.begin(), c.first.end());
        EXPECT_EQ(hmac_cpp::base64_encode(bin), c.second);
        std::vector<uint8_t> out;
        EXPECT_TRUE(hmac_cpp::base64_decode(c.second, out));
        EXPECT_EQ(out, bin);
    }
    std::vector<uint8_t> special = {0xfb, 0xff};
    EXPECT_EQ(hmac_cpp::base64_encode(special), "+/8=");
    EXPECT_EQ(hmac_cpp::base64_encode(special, hmac_cpp::Base64Alphabet::Url), "-_8=");
    hmac_cpp::secure_buffer<uint8_t> sec;
    EXPECT_TRUE(hmac_cpp::base64_decode("Zm9v", sec));
    std::string foo(sec.begin(), sec.end());
    EXPECT_EQ(foo, "foo");
    std::vector<uint8_t> out;
    EXPECT_TRUE(hmac_cpp::base64_decode("Zg", out, hmac_cpp::Base64Alphabet::Standard, false, false));
    EXPECT_EQ(out, std::vector<uint8_t>({'f'}));
    EXPECT_TRUE(hmac_cpp::base64_decode("+__/", out, hmac_cpp::Base64Alphabet::Url, false, false));
    EXPECT_EQ(out, std::vector<uint8_t>({0xfb,0xff,0xff}));
}

TEST(EncodingTest, Base64RejectsInvalid) {
    std::vector<uint8_t> out;
    EXPECT_FALSE(hmac_cpp::base64_decode("Zm9v$", out));
}

TEST(EncodingTest, Base32Vectors) {
    std::vector<std::pair<std::string,std::string>> cases = {
        {"f", "MY======"},
        {"fo", "MZXQ===="},
        {"foo", "MZXW6==="},
        {"foob", "MZXW6YQ="},
        {"fooba", "MZXW6YTB"},
        {"foobar", "MZXW6YTBOI======"}
    };
    for (auto& c : cases) {
        std::vector<uint8_t> bin(c.first.begin(), c.first.end());
        EXPECT_EQ(hmac_cpp::base32_encode(bin), c.second);
        std::vector<uint8_t> out;
        EXPECT_TRUE(hmac_cpp::base32_decode(c.second, out, /*require_padding=*/true));
        EXPECT_EQ(out, bin);
    }
    hmac_cpp::secure_buffer<uint8_t> sec;
    EXPECT_TRUE(hmac_cpp::base32_decode("MZXW6===", sec, true));
    std::string foo(sec.begin(), sec.end());
    EXPECT_EQ(foo, "foo");
}

TEST(EncodingTest, Base32CaseWhitespace) {
    std::vector<uint8_t> out;
    EXPECT_TRUE(hmac_cpp::base32_decode("my======", out, true, false));
    EXPECT_EQ(out, std::vector<uint8_t>({'f'}));
    EXPECT_TRUE(hmac_cpp::base32_decode("MY", out, false, false));
    EXPECT_EQ(out, std::vector<uint8_t>({'f'}));
    EXPECT_TRUE(hmac_cpp::base32_decode("MZXW6YTBOI======", out));
    EXPECT_EQ(std::string(out.begin(), out.end()), "foobar");
    EXPECT_TRUE(hmac_cpp::base32_decode("MZXW6 YTBO I======", out, true, false));
    EXPECT_EQ(std::string(out.begin(), out.end()), "foobar");
}

TEST(EncodingTest, Base36Vectors) {
    std::vector<uint8_t> z2 = {0x00, 0x00};
    EXPECT_EQ(hmac_cpp::base36_encode(z2.data(), z2.size()), "000");
    std::vector<uint8_t> out;
    EXPECT_TRUE(hmac_cpp::base36_decode("000", out));
    EXPECT_EQ(out, z2);
    std::vector<uint8_t> one = {0x01};
    EXPECT_EQ(hmac_cpp::base36_encode(one.data(), one.size()), "1");
    EXPECT_TRUE(hmac_cpp::base36_decode("1", out));
    EXPECT_EQ(out, one);
    std::mt19937 rng(0);
    std::uniform_int_distribution<int> dist(0,255);
    for (int len = 0; len < 16; ++len) {
        std::vector<uint8_t> buf(len);
        for (int i = 0; i < len; ++i) buf[i] = static_cast<uint8_t>(dist(rng));
        std::string enc = hmac_cpp::base36_encode(buf.data(), buf.size());
        std::vector<uint8_t> dec;
        EXPECT_TRUE(hmac_cpp::base36_decode(enc, dec));
        EXPECT_EQ(dec, buf);
    }
}

TEST(EncodingPropertyTest, Base64RoundTrip) {
    std::mt19937 rng(123);
    std::uniform_int_distribution<int> len_dist(0,64);
    for (int i = 0; i < 50; ++i) {
        int len = len_dist(rng);
        std::vector<uint8_t> buf(len);
        for (int j = 0; j < len; ++j) buf[j] = static_cast<uint8_t>(rng());
        for (auto alpha : {hmac_cpp::Base64Alphabet::Standard, hmac_cpp::Base64Alphabet::Url}) {
            for (bool pad : {true, false}) {
                std::string enc = hmac_cpp::base64_encode(buf.data(), buf.size(), alpha, pad);
                std::vector<uint8_t> dec;
                EXPECT_TRUE(hmac_cpp::base64_decode(enc, dec, alpha, pad, true));
                EXPECT_EQ(dec, buf);
                std::string re = hmac_cpp::base64_encode(dec.data(), dec.size(), alpha, pad);
                EXPECT_EQ(re, enc);
            }
        }
    }
}

TEST(EncodingPropertyTest, Base64StrictRejects) {
    std::vector<uint8_t> out;
    EXPECT_FALSE(hmac_cpp::base64_decode("+__/", out, hmac_cpp::Base64Alphabet::Url, false, true));
    EXPECT_FALSE(hmac_cpp::base64_decode("AAAAA", out, hmac_cpp::Base64Alphabet::Standard, false, true));
}

TEST(EncodingPropertyTest, Base32RoundTrip) {
    std::mt19937 rng(321);
    std::uniform_int_distribution<int> len_dist(0,40);
    for (int i = 0; i < 50; ++i) {
        int len = len_dist(rng);
        std::vector<uint8_t> buf(len);
        for (int j = 0; j < len; ++j) buf[j] = static_cast<uint8_t>(rng());
        for (bool pad : {true, false}) {
            std::string enc = hmac_cpp::base32_encode(buf.data(), buf.size(), pad);
            std::vector<uint8_t> dec;
            EXPECT_TRUE(hmac_cpp::base32_decode(enc, dec, pad, true));
            EXPECT_EQ(dec, buf);
            std::string re = hmac_cpp::base32_encode(dec.data(), dec.size(), pad);
            EXPECT_EQ(re, enc);
        }
    }
}

TEST(EncodingPropertyTest, Base32RejectsInvalid) {
    std::vector<uint8_t> out;
    EXPECT_FALSE(hmac_cpp::base32_decode("A", out));
    EXPECT_FALSE(hmac_cpp::base32_decode("AAA", out));
    EXPECT_FALSE(hmac_cpp::base32_decode("AAAAAA", out));
    EXPECT_FALSE(hmac_cpp::base32_decode("MZX=====MZXW6===", out));
}

TEST(EncodingPropertyTest, Base36LeadingZeros) {
    std::mt19937 rng(777);
    std::uniform_int_distribution<int> len_dist(0,10);
    for (int i = 0; i < 20; ++i) {
        int zeros = len_dist(rng) % 5;
        int data_len = len_dist(rng);
        std::vector<uint8_t> buf(zeros + data_len);
        for (int j = 0; j < data_len; ++j) buf[zeros + j] = static_cast<uint8_t>(rng());
        std::string enc = hmac_cpp::base36_encode(buf.data(), buf.size());
        std::vector<uint8_t> dec;
        EXPECT_TRUE(hmac_cpp::base36_decode(enc, dec));
        EXPECT_EQ(dec, buf);
    }
}

TEST(SecretStringTest, BasicOperations) {
    hmac_cpp::secret_string s("top-secret");
    std::string out;
    s.with_plaintext([&](const uint8_t* p, size_t n) {
        out.assign(reinterpret_cast<const char*>(p), n);
    });
    EXPECT_EQ(out, "top-secret");
    EXPECT_EQ(s.reveal_copy(), "top-secret");
    s.clear();
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.reveal_copy(), "");
}

TEST(SecretStringTest, MoveSemantics) {
    hmac_cpp::secret_string a("abc");
    hmac_cpp::secret_string b(std::move(a));
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(b.reveal_copy(), "abc");
}

TEST(SecretStringTest, NonceRotationPreservesPlaintext) {
    hmac_cpp::secret_string s("nonce-test");
    s.rotate_nonce();
    EXPECT_EQ(s.reveal_copy(), "nonce-test");
}

TEST(SecretStringTest, IntegrityCheckFailsOnTamper) {
    hmac_cpp::secret_string s("tamper");
    struct SecretStringAccessor {
        std::vector<uint8_t> ct;
        std::array<uint8_t,12> nonce;
        std::array<uint8_t,32> tag;
        bool locked;
    };
    auto* hack = reinterpret_cast<SecretStringAccessor*>(&s);
    hack->tag[0] ^= 0x01;
    EXPECT_THROW({
        s.with_plaintext([](const uint8_t*, size_t){});
    }, std::runtime_error);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

