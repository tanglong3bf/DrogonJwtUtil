/**
 * @file JwtUtil.cc
 * @brief A Drogon Plugin for JWT
 * @author tanglong3bf
 * @version 0.0.1
 * @date 2024-05-19
 * @copyright Copyright (c) 2024 tanglong3bf
 * @license MIT License
 */

#include "JwtUtil.h"
#include <drogon/utils/Utilities.h>

using namespace ::std;
using namespace ::drogon::utils;
using namespace ::trantor::utils;

using namespace ::tl::jwt;

string hmacSha256Encode(std::string secret, string payload)
{
    string result;

    // pre processing of the key
    string K;
    if (secret.size() > 64)
    {
        K = getSha256(secret.data(), secret.size());
    }
    else
    {
        K = secret;
    }
    if (K.size() < 64)
    {
        K.resize(64);
    }

    string ipadkey;
    ipadkey.resize(64);
    transform(K.begin(), K.end(), ipadkey.begin(), [](const auto c) -> char {
        return c ^ 0x36;
    });

    string opadkey;
    opadkey.resize(64);
    transform(K.begin(), K.end(), opadkey.begin(), [](const auto c) -> char {
        return c ^ 0x5c;
    });

    // ipadkey + payload
    string temp1;
    temp1.resize(64 + payload.size());
    copy(ipadkey.begin(), ipadkey.end(), temp1.begin());
    copy(payload.begin(), payload.end(), temp1.begin() + 64);

    // sha256(ipadkey + payload)
    auto hash1 = sha256(temp1.data(), temp1.size());

    // opadkey + sha256(ipadkey + payload)
    string temp2;
    temp2.resize(96);
    copy(opadkey.begin(), opadkey.end(), temp2.begin());
    copy(hash1.bytes, hash1.bytes + 32, temp2.begin() + opadkey.size());

    // sha256(opadkey + sha256(ipadkey + payload))
    auto hash2 = sha256(temp2.data(), temp2.size());
    return base64Encode(hash2.bytes, 32, true, false);
}

#define CHECK_AND_SET_S(key)                                             \
    if (payloadJson.isMember(#key))                                      \
    {                                                                    \
        assert(payloadJson[#key].isString());                            \
        this->key##_ =                                                   \
            std::make_shared<std::string>(payloadJson[#key].asString()); \
    }

void JwtUtil::initAndStart(const Json::Value& config)
{
    if (config.isMember("secret"))
    {
        assert(config["secret"].isString());
        LOG_WARN << "NOT SUGGEST to use secret in config file.";
        secret_ = config["secret"].asString();
    }

    if (!config.isMember("payload"))
    {
        LOG_WARN << "Config file is not found payload.";
        return;
    }
    assert(config["payload"].isObject());

    auto payloadJson = config["payload"];

    CHECK_AND_SET_S(iss);
    CHECK_AND_SET_S(sub);
    CHECK_AND_SET_S(aud);

    if (payloadJson.isMember("exp"))
    {
        assert(payloadJson["exp"].isInt());
        auto exp = payloadJson["exp"].asInt();
        if (exp >= 0)
        {
            this->exp_ = exp;
        }
    }
    if (payloadJson.isMember("nbf"))
    {
        assert(payloadJson["nbf"].isInt());
        this->nbf_ = payloadJson["nbf"].asInt();
    }
    if (payloadJson.isMember("jti"))
    {
        assert(payloadJson["jti"].isBool());
        this->jti_ = payloadJson["jti"].asBool();
    }
}

#undef CHECK_AND_SET_S

string JwtUtil::encode(const Json::Value& data)
{
    auto result = this->base64Header_;

    Json::Value payload;
    payload = data;
    if (this->iss_ && *this->iss_ != "")
    {
        payload["iss"] = *this->iss_;
    }
    if (this->sub_ && *this->sub_ != "")
    {
        payload["sub"] = *this->sub_;
    }
    if (this->aud_ && *this->aud_ != "")
    {
        payload["aud"] = *this->aud_;
    }
    // get current time
    auto iat = std::time(nullptr);
    payload["iat"] = iat;
    if (this->exp_ >= 0)
    {
        payload["exp"] = this->exp_ + iat;
    }
    if (this->nbf_ >= 0)
    {
        payload["nbf"] = this->nbf_ + iat;
    }
    if (this->jti_)
    {
        payload["jti"] = getUuid();
    }

    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    auto payloadStr = Json::writeString(builder, payload);

    auto payloadBase64 = drogon::utils::base64Encode(payloadStr, true, false);
    result += '.' + payloadBase64;

    auto signature = hmacSha256Encode(this->secret_, result);
    result += '.' + signature;

    return result;
}

pair<Result, shared_ptr<Json::Value>> JwtUtil::decode(const string& token)
{
    auto parts = drogon::utils::splitString(token, ".");
    if (parts.size() != 3)
    {
        return {InvalidToken, nullptr};
    }

    auto header = parts[0];
    auto payload = parts[1];
    auto signature = parts[2];

    // check header
    if (header != this->base64Header_)
    {
        auto headerStr = base64Decode(header);
        // string to Json::Value
        Json::Value headerValue;
        Json::Reader reader;
        if (!reader.parse(headerStr, headerValue))
        {
            return {InvalidHeader, nullptr};
        }
        if (!headerValue.isMember("alg") || headerValue["alg"] != "HS256")
        {
            return {InvalidAlgorithm, nullptr};
        }
    }

    if (signature != hmacSha256Encode(this->secret_, header + '.' + payload))
    {
        return {InvalidSignature, nullptr};
    }

    // decode payload
    auto payloadStr = base64Decode(payload);
    auto payloadValue = make_shared<Json::Value>();

    // string to Json::Value
    Json::Reader reader;
    reader.parse(payloadStr, *payloadValue);

    if (payloadValue->isMember("exp") && (*payloadValue)["exp"].isInt())
    {
        auto exp = (*payloadValue)["exp"].asInt();
        auto now = std::time(nullptr);
        if (exp < now)
        {
            return {ExpiredToken, nullptr};
        }
        Json::Value temp;
        payloadValue->removeMember("exp", &temp);
    }

    if (payloadValue->isMember("nbf") && (*payloadValue)["nbf"].isInt())
    {
        auto nbf = (*payloadValue)["nbf"].asInt();
        auto now = std::time(nullptr);
        if (nbf > now)
        {
            return {InvalidNotBefore, nullptr};
        }
        Json::Value temp;
        payloadValue->removeMember("nbf", &temp);
    }

    Json::Value temp;
    payloadValue->removeMember("iat", &temp);

    return {Ok, payloadValue};
}

void JwtUtil::shutdown()
{
}
