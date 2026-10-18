#pragma once
#include <string>

enum class EngineType { NONE, COCOS, UNITY, UE4, NATIVE };

namespace engine {
    EngineType detect();
    const char* name(EngineType t);
    bool kernelAcPresent(std::string* detectedName);
}

namespace cocos {
    bool detect();
    std::string dumpIntelScript();
    std::string extractKeyScript();
    std::string bypassHardCaseScript();
}

namespace unity {
    bool detect();
    std::string dumpIntelScript();
    std::string extractKeyScript();
    std::string bypassHardCaseScript();
}

namespace ue4 {
    bool detect();
    std::string dumpIntelScript();
    std::string extractKeyScript();
    std::string bypassHardCaseScript();
}

namespace nat {
    bool detect();
    std::string dumpIntelScript();
    std::string extractKeyScript();
    std::string bypassHardCaseScript();
}
