#include "panel.h"
#include "frida_bridge.h"
#include "modules.h"
#include "imgui.h"
#include <string>
#include <vector>
#include <mutex>
#include <cstring>
#include <atomic>

static std::mutex g_mtx;
static std::string g_intelBuf;
static std::string g_scanBuf;
static std::string g_resultBuf;
static std::vector<std::string> g_console;
static char g_cmdBuf[16384] = {0};
static char g_jsBuf[16384]  = {0};
static std::atomic<bool> g_init{false};
static EngineType g_engine = EngineType::NONE;
static std::string g_acWarn;

static void appendTo(std::string& dst, const std::string& s) {
    std::lock_guard<std::mutex> lk(g_mtx);
    dst += s;
    dst += "\n";
    if (dst.size() > 200000) dst.erase(0, dst.size() - 150000);
}

static void onFridaMessage(const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_console.push_back(msg);
    if (g_console.size() > 2000) g_console.erase(g_console.begin(), g_console.begin()+500);
    if (msg.find("\"type\":\"cocos_xxtea_key\"") != std::string::npos ||
        msg.find("\"type\":\"unity_classes\"")    != std::string::npos ||
        msg.find("\"type\":\"ue4_pe_samples\"")   != std::string::npos ||
        msg.find("\"type\":\"native_dumped\"")    != std::string::npos) {
        g_resultBuf += msg + "\n";
        if (g_resultBuf.size() > 200000) g_resultBuf.erase(0, 150000);
    }
}

static void runScript(const std::string& js, const char* tagName) {
    auto& fb = FridaBridge::instance();
    if (!fb.isConnected()) {
        fb.connectRemote("127.0.0.1", 27042);
        fb.attachSelf();
    }
    if (!fb.executeScript(js)) {
        appendTo(g_resultBuf, std::string("[") + tagName + "] EXEC FAILED");
    } else {
        appendTo(g_resultBuf, std::string("[") + tagName + "] script dispatched");
    }
}

static void doDetect() {
    g_engine = engine::detect();
    std::string acName;
    bool ac = engine::kernelAcPresent(&acName);
    g_acWarn = ac ? std::string("KERNEL AC DETECTED - ") + acName + " - NOT SUPPORTED" : std::string("");
    std::lock_guard<std::mutex> lk(g_mtx);
    g_intelBuf.clear();
    g_intelBuf += "engine: ";
    g_intelBuf += engine::name(g_engine);
    g_intelBuf += "\n";
    if (ac) g_intelBuf += g_acWarn + "\n";
    g_intelBuf += "\n--- /proc/self/maps ---\n";
    FILE* f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "cocos") || strstr(line, "il2cpp") || strstr(line, "unity") ||
                strstr(line, "UE4")   || strstr(line, "Unreal") ||
                strstr(line, "ace")   || strstr(line, "battleye") ||
                strstr(line, "eac")   || strstr(line, "vanguard")) {
                g_intelBuf += line;
            }
        }
        fclose(f);
    }
}

static void callModuleDumpIntel() {
    switch (g_engine) {
        case EngineType::COCOS:  runScript(cocos::dumpIntelScript(), "cocos-intel"); break;
        case EngineType::UNITY:  runScript(unity::dumpIntelScript(), "unity-intel"); break;
        case EngineType::UE4:    runScript(ue4::dumpIntelScript(),   "ue4-intel");   break;
        case EngineType::NATIVE: runScript(nat::dumpIntelScript(),   "native-intel");break;
        default: break;
    }
}
static void callModuleExtractKey() {
    switch (g_engine) {
        case EngineType::COCOS:  runScript(cocos::extractKeyScript(), "cocos-key"); break;
        case EngineType::UNITY:  runScript(unity::extractKeyScript(), "unity-key"); break;
        case EngineType::UE4:    runScript(ue4::extractKeyScript(),   "ue4-key");   break;
        case EngineType::NATIVE: runScript(nat::extractKeyScript(),   "native-key");break;
        default: break;
    }
}
static void callModuleHardCase() {
    switch (g_engine) {
        case EngineType::COCOS:  runScript(cocos::bypassHardCaseScript(), "cocos-hard"); break;
        case EngineType::UNITY:  runScript(unity::bypassHardCaseScript(), "unity-hard"); break;
        case EngineType::UE4:    runScript(ue4::bypassHardCaseScript(),   "ue4-hard");   break;
        case EngineType::NATIVE: runScript(nat::bypassHardCaseScript(),   "native-hard");break;
        default: break;
    }
}

void panel_init() {
    if (g_init.exchange(true)) return;
    FridaBridge::instance().setMessageCallback(onFridaMessage);
}

static void drawReadonly(const char* id, const std::string& text) {
    std::string copy = text;
    ImGui::InputTextMultiline(id, (char*)copy.c_str(), copy.size() + 1,
                              ImVec2(-1, -1), ImGuiInputTextFlags_ReadOnly);
}

void panel_render() {
    if (ImGui::BeginTabBar("##lemon_tabs")) {
        if (ImGui::BeginTabItem("Intel")) {
            if (ImGui::Button("Detect##intel")) doDetect();
            ImGui::SameLine();
            if (ImGui::Button("Run module dumpIntel")) callModuleDumpIntel();
            ImGui::Separator();
            drawReadonly("##intel_buf", g_intelBuf);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Scan")) {
            if (ImGui::Button("ExtractKey")) callModuleExtractKey();
            ImGui::SameLine();
            if (ImGui::Button("BypassHardCase")) callModuleHardCase();
            ImGui::Separator();
            drawReadonly("##scan_buf", g_scanBuf);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Command")) {
            ImGui::TextUnformatted("Paste JS Frida here:");
            ImGui::InputTextMultiline("##cmdbuf", g_cmdBuf, sizeof(g_cmdBuf),
                                      ImVec2(-1, ImGui::GetTextLineHeight()*16));
            if (ImGui::Button("Run JS")) runScript(std::string(g_cmdBuf), "manual");
            ImGui::SameLine();
            if (ImGui::Button("Clear")) { memset(g_cmdBuf, 0, sizeof(g_cmdBuf)); }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Result")) {
            if (ImGui::Button("Clear result")) { std::lock_guard<std::mutex> lk(g_mtx); g_resultBuf.clear(); }
            ImGui::Separator();
            drawReadonly("##res_buf", g_resultBuf);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Frida Console")) {
            if (ImGui::Button("Connect")) {
                auto& fb = FridaBridge::instance();
                fb.connectRemote("127.0.0.1", 27042);
                fb.attachSelf();
            }
            ImGui::SameLine();
            if (ImGui::Button("Disconnect")) FridaBridge::instance().disconnect();
            ImGui::SameLine();
            if (ImGui::Button("Clear console")) { std::lock_guard<std::mutex> lk(g_mtx); g_console.clear(); }
            ImGui::Separator();
            if (ImGui::BeginChild("##consc", ImVec2(-1, ImGui::GetTextLineHeight()*14))) {
                std::lock_guard<std::mutex> lk(g_mtx);
                for (auto& l : g_console) ImGui::TextUnformatted(l.c_str());
            }
            ImGui::EndChild();
            ImGui::InputTextMultiline("##jsbuf", g_jsBuf, sizeof(g_jsBuf),
                                      ImVec2(-1, ImGui::GetTextLineHeight()*6));
            if (ImGui::Button("Run console JS")) runScript(std::string(g_jsBuf), "console");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}
