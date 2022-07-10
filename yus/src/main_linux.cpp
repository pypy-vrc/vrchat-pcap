#include <stdio.h>
#include "napi.h"

Napi::Value yus(const Napi::CallbackInfo &info)
{
    auto env = info.Env();

    printf("yus called\n");

    return env.Undefined();
}

Napi::Object init(Napi::Env env, Napi::Object exports)
{
    exports.Set(
        "yus",
        Napi::Function::New(env, yus));

    return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, init);
