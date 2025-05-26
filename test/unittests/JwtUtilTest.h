#include "../../src/JwtUtil.h"
#include <gtest/gtest.h>
#include <drogon/drogon.h>
#include <json/value.h>

TEST(TestToString, Test)
{
    EXPECT_STREQ("Ok", tl::jwt::toString(tl::jwt::Ok).c_str());
    EXPECT_STREQ("InvalidToken",
                 tl::jwt::toString(tl::jwt::InvalidToken).c_str());
    EXPECT_STREQ("InvalidSignature",
                 tl::jwt::toString(tl::jwt::InvalidSignature).c_str());
    EXPECT_STREQ("InvalidHeader",
                 tl::jwt::toString(tl::jwt::InvalidHeader).c_str());
    EXPECT_STREQ("InvalidAlgorithm",
                 tl::jwt::toString(tl::jwt::InvalidAlgorithm).c_str());
    EXPECT_STREQ("InvalidPayload",
                 tl::jwt::toString(tl::jwt::InvalidPayload).c_str());
    EXPECT_STREQ("InvalidNotBefore",
                 tl::jwt::toString(tl::jwt::InvalidNotBefore).c_str());
    EXPECT_STREQ("ExpiredToken",
                 tl::jwt::toString(tl::jwt::ExpiredToken).c_str());
}

TEST(TestInitAndStart, WithoutConfig)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    ASSERT_NO_THROW(jwtUtil->initAndStart({}));
    ASSERT_NO_THROW(jwtUtil->shutdown());
}

TEST(TestInitAndStart, WithSecret)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    Json::Value config;
    config["secret"] = "short";
    ASSERT_NO_THROW(jwtUtil->initAndStart(config));
    ASSERT_NO_THROW(jwtUtil->shutdown());
}

TEST(TestInitAndStart, WithSecretAndEmptyPayload)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    Json::Value config;
    config["secret"] = "short";
    config["payload"] = Json::Value(Json::objectValue);
    ASSERT_NO_THROW(jwtUtil->initAndStart(config));
    ASSERT_NO_THROW(jwtUtil->shutdown());
}

TEST(TestInitAndStart, WithPayload)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    Json::Value config;
    config["payload"]["iss"] = "tanglong3bf";
    config["payload"]["sub"] = "test";
    config["payload"]["aud"] = "user";
    config["payload"]["exp"] = -1;
    config["payload"]["nbf"] = -1;
    config["payload"]["jti"] = false;
    ASSERT_NO_THROW(jwtUtil->initAndStart(config));
    jwtUtil->shutdown();
}

TEST(TestInitAndStart, WithPositiveExp)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    Json::Value config;
    config["payload"]["exp"] = 1;
    ASSERT_NO_THROW(jwtUtil->initAndStart(config));
    jwtUtil->shutdown();
}

TEST(TestEncode, WithShortSecretAndEmptyPayload)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    jwtUtil->setSecret("short");
    Json::Value data;
    data["user_id"] = 1;
    data["username"] = "tanglong3bf";
    ASSERT_NO_THROW(jwtUtil->encode(data));
    jwtUtil->shutdown();
}

TEST(TestEncode, WithShortSecretAndPayload)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    jwtUtil->setSecret("short");
    Json::Value config;
    config["payload"]["iss"] = "tanglong3bf";
    config["payload"]["sub"] = "test";
    config["payload"]["aud"] = "user";
    config["payload"]["exp"] = -1;
    config["payload"]["nbf"] = -1;
    config["payload"]["jti"] = true;
    jwtUtil->initAndStart(config);
    Json::Value data;
    data["user_id"] = 1;
    data["username"] = "tanglong3bf";
    ASSERT_NO_THROW(jwtUtil->encode(data));
    jwtUtil->shutdown();
}

TEST(TestEncode, WithLongSecretAndNbf)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    jwtUtil->setSecret(
        "This is a very very very long secret, which is longer than 256 bits.");
    Json::Value config;
    config["payload"]["nbf"] = 1;
    jwtUtil->initAndStart(config);
    Json::Value data;
    data["user_id"] = 1;
    data["username"] = "tanglong3bf";
    ASSERT_NO_THROW(jwtUtil->encode(data));
    jwtUtil->shutdown();
}

TEST(TestDecode, InvalidToken)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    auto result = jwtUtil->decode("aaaaa.bbbbb");
    ASSERT_EQ(result.first, tl::jwt::InvalidToken)
        << "result.first: " << toString(result.first);
    jwtUtil->shutdown();
}

TEST(TestDecode, InvalidHeader2)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    auto result = jwtUtil->decode("aaaaa.bbbbb.ccccc");
    ASSERT_EQ(result.first, tl::jwt::InvalidHeader)
        << "result.first: " << toString(result.first);
    jwtUtil->shutdown();
}

TEST(TestDecode, InvalidAlgorithm)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    auto result =
        jwtUtil->decode("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.bbbbb.ccccc");
    ASSERT_EQ(result.first, tl::jwt::InvalidAlgorithm)
        << "result.first: " << toString(result.first);
    jwtUtil->shutdown();
}

TEST(TestDecode, InvalidSignature)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    // verify signature replaced the first letter from 'i' to 'a'
    auto result = jwtUtil->decode(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InRhbmdsb25nM2JmIiwiaWF0IjoxNzE2MDgyMD"
        "M5LCJleHAiOjE3MTYwODM4Mzl9.aLlW143H5y9wpNAFJTROHQIy-gDbGIPZPy_"
        "JFeKH1Ns");
    ASSERT_EQ(result.first, tl::jwt::InvalidSignature)
        << "result.first: " << toString(result.first);
    jwtUtil->shutdown();
}

TEST(TestEncodeAndDecode, InvalidExp)
{
    using namespace std::chrono;
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    jwtUtil->setSecret("secret");
    Json::Value config;
    config["payload"]["exp"] = 1;
    jwtUtil->initAndStart(config);
    auto jwt = jwtUtil->encode({});
    std::this_thread::sleep_for(2s);
    auto result = jwtUtil->decode(jwt);
    ASSERT_EQ(result.first, tl::jwt::ExpiredToken)
        << "result.first: " << toString(result.first);
    jwtUtil->shutdown();
}

TEST(TestEncodeAndDecode, InvalidNbf)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    jwtUtil->setSecret("secret");
    Json::Value config;
    config["payload"]["nbf"] = 1;
    jwtUtil->initAndStart(config);
    auto jwt = jwtUtil->encode({});
    auto result = jwtUtil->decode(jwt);
    ASSERT_EQ(result.first, tl::jwt::InvalidNotBefore)
        << "result.first: " << toString(result.first);
    jwtUtil->shutdown();
}

TEST(TestEncodeAndDecode, OkWithNbf)
{
    using namespace std::chrono;
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    jwtUtil->setSecret("secret");
    Json::Value config;
    config["payload"]["nbf"] = 1;
    jwtUtil->initAndStart(config);
    auto jwt = jwtUtil->encode({});
    std::cout << jwt << std::endl;
    std::this_thread::sleep_for(2s);
    auto result = jwtUtil->decode(jwt);
    ASSERT_EQ(result.first, tl::jwt::Ok);
    ASSERT_NE(result.second, nullptr);
    auto payload = result.second;
    ASSERT_TRUE(payload->isObject());
    jwtUtil->shutdown();
}

TEST(TestOtherAlgorithms, HS384)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    jwtUtil->setSecret("secret");
    Json::Value config;
    config["alg"] = "HS384";
    jwtUtil->initAndStart(config);
    auto jwt = jwtUtil->encode({});
    std::cout << jwt << std::endl;
    auto result = jwtUtil->decode(jwt);
    ASSERT_EQ(result.first, tl::jwt::Ok);
    ASSERT_NE(result.second, nullptr);
    auto payload = result.second;
    ASSERT_TRUE(payload->isObject());
    jwtUtil->shutdown();
}

TEST(TestOtherAlgorithms, HS512)
{
    auto jwtUtil = std::make_unique<tl::jwt::JwtUtil>();
    jwtUtil->setSecret("secret");
    Json::Value config;
    config["alg"] = "HS512";
    jwtUtil->initAndStart(config);
    auto jwt = jwtUtil->encode({});
    std::cout << jwt << std::endl;
    auto result = jwtUtil->decode(jwt);
    ASSERT_EQ(result.first, tl::jwt::Ok);
    ASSERT_NE(result.second, nullptr);
    auto payload = result.second;
    ASSERT_TRUE(payload->isObject());
    jwtUtil->shutdown();
}
