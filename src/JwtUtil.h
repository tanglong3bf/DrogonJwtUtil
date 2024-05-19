/**
 * @file JwtUtil.h
 * @brief A Drogon Plugin for JWT
 * @author tanglong3bf
 * @version 0.0.1
 * @date 2024-05-19
 * @copyright Copyright (c) 2024 tanglong3bf
 * @license MIT License
 */

#pragma once

#include <drogon/plugins/Plugin.h>

namespace tl::jwt
{

/// The result of decoding a jwt token.
enum Result
{
    Ok = 0,            ///< parsing success
    InvalidToken,      ///< token format is not correct
    InvalidSignature,  ///< signature is not correct
    InvalidHeader,     ///< header is not correct
    InvalidAlgorithm,  ///< not supported algorithm
    InvalidPayload,    ///< payload is not correct
    InvalidNotBefore,  ///< token is not valid before nbf
    ExpiredToken,      ///< token is expired
};

inline std::string to_string(Result result)
{
    switch (result)
    {
        case Ok:
            return "Ok";
        case InvalidToken:
            return "InvalidToken";
        case InvalidSignature:
            return "InvalidSignature";
        case InvalidHeader:
            return "InvalidHeader";
        case InvalidAlgorithm:
            return "InvalidAlgorithm";
        case InvalidPayload:
            return "InvalidPayload";
        case InvalidNotBefore:
            return "InvalidNotBefore";
        case ExpiredToken:
            return "ExpiredToken";
    }
    return "Unknown";
}

/**
 * @brief JWT Util
 * @author tanglong3bf
 * @date 2024-05-19
 */
class JwtUtil : public drogon::Plugin<JwtUtil>
{
  public:
    /**
     * @brief You can set secret_ in the constructor, for example:
     * @code
     *     // tanglong3bf
     *     this->secret_ = drogon::utils::base64Decode("dGFuZ2xvbmczYmY=");
     * @endcode
     */
    JwtUtil()
    {
    }

    /// This method must be called by drogon to initialize and start the plugin.
    /// It must be implemented by the user.
    void initAndStart(const Json::Value& config) override;

    /**
     * @brief encode jwt
     * @param [in] data The payload to be encoded. If the payload contains the
     * "iat", "exp", "nbf", ... fields, they may be overriden.
     * @return The encoded jwt string.
     */
    std::string encode(const Json::Value& data);

    /**
     * @brief decode jwt
     * @param [in] token The jwt string to be decoded.
     * @return A pair of Result and the payload. If the Result is Ok, the
     * payload is valid. The iat, exp, nbf, ... fields will be removed from the
     * payload.
     *   @retval Ok Decode success and payload is valid.
     *   @retval others Decode failed, see Result.
     * @see Result
     */
    std::pair<Result, std::shared_ptr<Json::Value>> decode(
        const std::string& token);

    /// This method must be called by drogon to shutdown the plugin.
    /// It must be implemented by the user.
    void shutdown() override;

  private:
    std::string secret_;
    /// header: {"alg":"HS256","typ":"JWT"}
    const std::string base64Header_{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"};
    // payload
    std::shared_ptr<std::string> iss_;
    std::shared_ptr<std::string> sub_;
    std::shared_ptr<std::string> aud_;

    int exp_{1800};
    int nbf_{-1};
    bool jti_ = false;
};

}  // namespace tl::jwt
