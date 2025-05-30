# JwtUtil

A simple JWT (JSON Web Token) generator and verifier for [Drogon](https://github.com/drogonframework/drogon)(C++ web framework).

# How to use

## Install

For the default drogon project, you need create a new subdirectory in the plugins directory of the project.

Like this:

```shell
$ tree .
.
├── CMakeLists.txt
├── config.json
├── main.cc
└── plugins
    └── tl
        └── jwt
```

And then, copy all files in the src directory to the new subdirectory.

Like this:

```shell
$ tree .
.
├── CMakeLists.txt
├── config.json
├── main.cc
└── plugins
    └── tl
        └── jwt
            ├── JwtUtil.cc
            ├── JwtUtil.h
            └── sha2.h
```

Finally, modify the CMakeLists.txt file of the drogon project so that this plugin can be compiled into the project.

```cmake
# ...
aux_source_directory(plugins/tl/jwt JWT_SRC)
# ...
target_sources(${PROJECT_NAME}
               PRIVATE
               ${SRC_DIR}
               ${CTL_SRC}
               ${FILTER_SRC}
               ${PLUGIN_SRC}
               ${MODEL_SRC}
               ${JWT_SRC})
```

## config

In the config.yaml file of the drogon project, add the following configuration:

```yaml
plugins:
  - name: tl::jwt::JwtUtil
    config:
      # secret: The secret key used to sign and verify JWT tokens. NOT
      # SUGGESTED to set in config file.
      secret: your_secret_key
      # alg: The algorithm used to sign and verify JWT tokens. HS256 by default.
      # Supported algorithms: HS256(default), HS384, HS512
      alg: HS256
      # iat is MUST NOT set. It will be set in code automatically.
      payload:
        # three string fields are not necessary.
        iss: tanglong3bf
        sub: demo
        aud: visitor
        # exp: expired time in seconds, if it is negative, means always not
        # expired. 1800 by default.
        exp: 1800
        # nbf: not before time in seconds, if it is negative, means not set this
        # field to payload. -1 by default.
        nbf: -1
        # jti: JWT ID, if it is false, means not set this field to payload. If
        # it is true, the UUID will be used to generate the jti field. False by
        # default.
        jti: false
```

In the config.json file of the drogon project, add the following configuration:

```json
"plugins" : [
    {
        "name": "tl::jwt::JwtUtil",
        "config": {
            // secret: The secret key used to sign and verify JWT tokens. NOT
            // SUGGESTED to set in config file.
            "secret": "your_secret_key",
            // alg: The algorithm used to sign and verify JWT tokens. HS256 by
            // default.
            // Supported algorithms: HS256(default), HS384, HS512
            "alg": "HS256",
            // iat is MUST NOT set. It will be set in code automatically.
            "payload": {
                // three string fields are not necessary.
                "iss": "tanglong3bf",
                "sub": "demo",
                "aud": "visitor",
                // exp: expired time in seconds, if it is negative, means always
                // not expired. 1800 by default.
                "exp": 1800,
                // nbf: not before time in seconds, if it is negative, means not
                // set this field to payload. -1 by default.
                "nbf": -1,
                // jti: JWT ID, if it is false, means not set this field to
                // payload. If it is true, the UUID will be used to generate the
                // jti field. False by default.
                "jti": false
            }
        }
    }
]
```

# examples

```cpp
// using namespace drogon;
// using namespace drogon::utils;
// using namespace tl::jwt;
// set secret key
app().registerBeginningAdvice([] {
     JwtUtil jwtUtil = app().getPlugin<JwtUtil>();
     // tanglong3bf
     jwtUtil.setSecret(base64Decode("dGFuZ2xvbmczYmY="));
});

// generate and verify JWT token
app().registerBeginningAdvice([] {
    auto jwtUtil = app().getPlugin<JwtUtil>();

    Json::Value data;
    data["user_id"] = 1;
    data["role"] = "admin";

    // std::string
    auto jwt = jwtUtil->encode(data);
    LOG_INFO << "jwt: " << jwt;

    // std::pair<Result, shared_ptr<Json::Value>>
    auto result = jwtUtil->decode(jwt);
    if (result.first == Ok)
    {
        LOG_INFO << "decode success";
        LOG_INFO << result.second->toStyledString();
    }
    else
    {
        LOG_ERROR << toString(result.first);
    }
});
```
