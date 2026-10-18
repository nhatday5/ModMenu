#pragma once
#include <string>
#include <functional>
#include <mutex>
#include <atomic>
#include <vector>

extern "C" {
#include <frida-core.h>
}

class FridaBridge {
public:
    static FridaBridge& instance();

    bool connectRemote(const std::string& host, int port);
    bool attachSelf();
    bool executeScript(const std::string& js);
    void disconnect();

    void setMessageCallback(std::function<void(const std::string&)> cb);
    void pushLog(const std::string& line);
    std::vector<std::string> drainLogs();
    bool isConnected() const { return connected.load(); }

private:
    FridaBridge() = default;
    ~FridaBridge();
    FridaBridge(const FridaBridge&) = delete;
    FridaBridge& operator=(const FridaBridge&) = delete;

    static void onMessageCb(FridaScript* script, const gchar* message, GBytes* data, gpointer user_data);

    FridaDeviceManager* mgr = nullptr;
    FridaDevice* device = nullptr;
    FridaSession* session = nullptr;
    FridaScript* script = nullptr;
    std::mutex apiMtx;
    std::mutex logMtx;
    std::vector<std::string> logs;
    std::function<void(const std::string&)> msgCb;
    std::atomic<bool> connected{false};
};
