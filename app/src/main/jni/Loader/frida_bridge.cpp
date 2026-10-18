#include "frida_bridge.h"
#include <android/log.h>
#include <unistd.h>
#include <cstring>
#include <ctime>

#define TAG "FridaBridge"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static std::string nowStamp() {
    time_t t = time(nullptr);
    struct tm tmv;
    localtime_r(&t, &tmv);
    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);
    return std::string(buf);
}

FridaBridge& FridaBridge::instance() {
    static FridaBridge inst;
    return inst;
}

FridaBridge::~FridaBridge() { disconnect(); }

void FridaBridge::pushLog(const std::string& line) {
    std::lock_guard<std::mutex> lk(logMtx);
    logs.push_back("[" + nowStamp() + "] " + line);
    if (logs.size() > 4000) logs.erase(logs.begin(), logs.begin() + 1000);
}

std::vector<std::string> FridaBridge::drainLogs() {
    std::lock_guard<std::mutex> lk(logMtx);
    std::vector<std::string> out;
    out.swap(logs);
    return out;
}

void FridaBridge::setMessageCallback(std::function<void(const std::string&)> cb) {
    std::lock_guard<std::mutex> lk(apiMtx);
    msgCb = std::move(cb);
}

void FridaBridge::onMessageCb(FridaScript* s, const gchar* message, GBytes* data, gpointer user_data) {
    (void)s;
    auto* self = static_cast<FridaBridge*>(user_data);
    std::string m = message ? message : "{}";
    if (data) {
        gsize size = 0;
        const gchar* d = static_cast<const gchar*>(g_bytes_get_data(data, &size));
        if (d && size > 0) {
            static const char* hex = "0123456789abcdef";
            std::string hx;
            hx.reserve(size * 2 + 16);
            hx += " [bin:";
            for (gsize i = 0; i < size; ++i) {
                unsigned char b = static_cast<unsigned char>(d[i]);
                hx += hex[b >> 4];
                hx += hex[b & 0xF];
            }
            hx += "]";
            m += hx;
        }
    }
    self->pushLog(m);
    std::function<void(const std::string&)> cbCopy;
    {
        std::lock_guard<std::mutex> lk(self->apiMtx);
        cbCopy = self->msgCb;
    }
    if (cbCopy) cbCopy(m);
}

bool FridaBridge::connectRemote(const std::string& host, int port) {
    std::lock_guard<std::mutex> lk(apiMtx);
    if (connected.load()) return true;
    frida_init();
    mgr = frida_device_manager_new();
    GError* err = nullptr;
    std::string addr = host + ":" + std::to_string(port);
    device = frida_device_manager_add_remote_device_sync(mgr, "patched", addr.c_str(), nullptr, &err);
    if (!device) {
        std::string msg = err ? err->message : "unknown";
        if (err) g_error_free(err);
        pushLog("connectRemote failed: " + msg);
        return false;
    }
    pushLog("remote device added: " + addr);
    return true;
}

bool FridaBridge::attachSelf() {
    std::lock_guard<std::mutex> lk(apiMtx);
    if (!device) { pushLog("attachSelf: no device"); return false; }
    if (session) { connected = true; return true; }
    GError* err = nullptr;
    pid_t pid = getpid();
    session = frida_device_attach_sync(device, pid, nullptr, nullptr, &err);
    if (!session) {
        std::string msg = err ? err->message : "unknown";
        if (err) g_error_free(err);
        pushLog("attachSelf failed: " + msg);
        return false;
    }
    connected.store(true);
    pushLog("attached to pid " + std::to_string(pid));
    return true;
}

bool FridaBridge::executeScript(const std::string& js) {
    std::lock_guard<std::mutex> lk(apiMtx);
    if (!session) { pushLog("executeScript: not attached"); return false; }
    GError* err = nullptr;
    if (script) {
        frida_script_unload_sync(script, nullptr, nullptr);
        g_object_unref(script);
        script = nullptr;
    }
    script = frida_session_create_script_sync(session, js.c_str(), nullptr, nullptr, &err);
    if (!script) {
        std::string msg = err ? err->message : "unknown";
        if (err) g_error_free(err);
        pushLog("createScript failed: " + msg);
        return false;
    }
    g_signal_connect(script, "message", G_CALLBACK(onMessageCb), this);
    frida_script_load_sync(script, nullptr, &err);
    if (err) {
        std::string msg = err->message;
        g_error_free(err);
        pushLog("script load failed: " + msg);
        return false;
    }
    pushLog("script loaded (" + std::to_string(js.size()) + " bytes)");
    return true;
}

void FridaBridge::disconnect() {
    std::lock_guard<std::mutex> lk(apiMtx);
    if (script) {
        frida_script_unload_sync(script, nullptr, nullptr);
        g_object_unref(script);
        script = nullptr;
    }
    if (session) {
        frida_session_detach_sync(session, nullptr, nullptr);
        g_object_unref(session);
        session = nullptr;
    }
    if (device) { g_object_unref(device); device = nullptr; }
    if (mgr) {
        frida_device_manager_close_sync(mgr, nullptr, nullptr);
        g_object_unref(mgr);
        mgr = nullptr;
    }
    connected.store(false);
}
