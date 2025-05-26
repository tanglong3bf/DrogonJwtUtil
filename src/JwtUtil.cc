/**
 * @file JwtUtil.cc
 *
 * @copyright Copyright (c) 2024 - 2025 tanglong3bf
 * @license MIT License
 */

#include "JwtUtil.h"
#include <drogon/utils/Utilities.h>
#include "sha2.h"

using namespace std;
using namespace drogon::utils;

using namespace tl::jwt;

inline function<string(const string&)> getHashFunc(Algorithm alg)
{
    switch (alg)
    {
        case HS256:
            return sha2::sha256;
        case HS384:
            return sha2::sha384;
        case HS512:
            return sha2::sha512;
    }
}

string hmacEncode(const string& secret,
                  const string& headerAndPayload,
                  Algorithm alg)
{
    auto hashFunc = getHashFunc(alg);
    // pre processing of the key
    string K = secret;
    if ((alg == HS256 && secret.size() > 64) || secret.size() > 128)
    {
        K = hashFunc(secret);
    }
    if (alg == HS256 && K.size() < 64)
    {
        K.resize(64, '\0');
    }
    else if (K.size() < 128)
    {
        K.resize(128, '\0');
    }

    // Create ipadkey and opadkey
    string ipadkey(K.size(), '\0');
    string opadkey(K.size(), '\0');

    transform(K.begin(), K.end(), ipadkey.begin(), [](const auto c) -> char {
        return c ^ 0x36;
    });
    transform(K.begin(), K.end(), opadkey.begin(), [](const auto c) -> char {
        return c ^ 0x5c;
    });

    // hash(ipadkey + headerAndPayload)
    auto hash1 = hashFunc(ipadkey + headerAndPayload);

    // hash(opadkey + hash(ipadkey + headerAndPayload))
    auto hash2 = hashFunc(opadkey + hash1);
    return base64Encode(hash2, true, false);
}

#define CHECK_AND_SET_S(key)                                              \
    if (payloadJson.isMember(#key))                                       \
    {                                                                     \
        assert(payloadJson[#key].isString());                             \
        this->key##_ = make_shared<string>(payloadJson[#key].asString()); \
    }

void JwtUtil::initAndStart(const Json::Value& config)
{
    if (config.isMember("secret"))
    {
        assert(config["secret"].isString());
        LOG_WARN << "NOT SUGGEST to use secret in config file.";
        secret_ = config["secret"].asString();
    }

    if (config.isMember("alg"))
    {
        assert(config["alg"].isString());
        try
        {
            alg_ = fromString(config["alg"].asString());
        }
        catch (const out_of_range& e)
        {
            LOG_ERROR << "Invalid algorithm: " << config["alg"].asString();
            LOG_ERROR << "Supported algorithms: HS256, HS384, HS512.";
            exit(1);
        }
    }
    else
    {
        alg_ = HS256;
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
    auto result = base64HeaderList.at(this->alg_);

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
    auto iat = time(nullptr);
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

    auto signature = hmacEncode(this->secret_, result, this->alg_);

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

    Json::CharReaderBuilder builder;
    auto reader = unique_ptr<Json::CharReader>(builder.newCharReader());

    // check header
    if (header != base64HeaderList.at(alg_))
    {
        auto headerStr = base64Decode(header);
        // string to Json::Value
        Json::Value headerValue;
        if (!reader->parse(headerStr.data(),
                           headerStr.data() + headerStr.size(),
                           &headerValue,
                           nullptr))
        {
            return {InvalidHeader, nullptr};
        }
        if (!headerValue.isMember("alg") || headerValue["alg"] != alg_)
        {
            return {InvalidAlgorithm, nullptr};
        }
    }

    if (signature !=
        hmacEncode(this->secret_, header + '.' + payload, this->alg_))
    {
        return {InvalidSignature, nullptr};
    }

    // decode payload
    auto payloadStr = base64Decode(payload);
    auto payloadValue = make_shared<Json::Value>();

    // string to Json::Value
    reader->parse(payloadStr.data(),
                  payloadStr.data() + payloadStr.size(),
                  payloadValue.get(),
                  nullptr);

    if (payloadValue->isMember("exp") && (*payloadValue)["exp"].isInt())
    {
        auto exp = (*payloadValue)["exp"].asInt();
        auto now = time(nullptr);
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
        auto now = time(nullptr);
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
