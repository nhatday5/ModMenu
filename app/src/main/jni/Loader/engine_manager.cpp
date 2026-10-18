#include "modules.h"
#include <fstream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <android/log.h>

#define TAG "EngineMgr"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static bool mapsHas(const char* needle) {
    std::ifstream f("/proc/self/maps");
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.find(needle) != std::string::npos) return true;
    }
    return false;
}

EngineType engine::detect() {
    if (mapsHas("libUE4.so") || mapsHas("libUnreal.so")) return EngineType::UE4;
    if (mapsHas("libil2cpp.so") || mapsHas("libunity.so")) return EngineType::UNITY;
    if (mapsHas("libcocos2djs.so") || mapsHas("libcocos2d.so") ||
        mapsHas("libcocos.so") || mapsHas("libCocos2d-x.so")) return EngineType::COCOS;
    return EngineType::NATIVE;
}

const char* engine::name(EngineType t) {
    switch (t) {
        case EngineType::COCOS:  return "Cocos2d-x";
        case EngineType::UNITY:  return "Unity IL2CPP";
        case EngineType::UE4:    return "Unreal Engine 4";
        case EngineType::NATIVE: return "Native (.so)";
        default:                 return "Unknown";
    }
}

bool engine::kernelAcPresent(std::string* detected) {
    static const char* acNames[] = {
        "ace", "battleye", "eac", "easyanticheat", "vanguard",
        "nprotect", "gameguard", "xigncode", "tenprotect", "tencent.ace"
    };
    {
        std::ifstream f("/proc/modules");
        if (f) {
            std::string line;
            while (std::getline(f, line)) {
                for (auto* a : acNames) {
                    if (line.find(a) != std::string::npos) {
                        if (detected) *detected = std::string("kmod:") + a;
                        return true;
                    }
                }
            }
        }
    }
    {
        std::ifstream f("/proc/self/maps");
        if (f) {
            std::string line;
            while (std::getline(f, line)) {
                for (auto* a : acNames) {
                    if (line.find(a) != std::string::npos) {
                        if (detected) *detected = std::string("lib:") + a;
                        return true;
                    }
                }
            }
        }
    }
    static const char* devPaths[] = {
        "/dev/tencent_ace", "/dev/ace", "/dev/battleye",
        "/dev/eac", "/dev/vgk", "/proc/tencent_ace"
    };
    for (auto* p : devPaths) {
        if (access(p, F_OK) == 0) {
            if (detected) *detected = std::string("dev:") + p;
            return true;
        }
    }
    return false;
}
