#include "../modules.h"

namespace nat {

bool detect() { return true; }

std::string dumpIntelScript() {
    return R"JS(
(function(){
    var maps = Process.enumerateModules();
    var out = [];
    for (var i=0;i<maps.length;i++){
        var n = maps[i].name;
        if (n.indexOf(".so")<0) continue;
        if (n.indexOf("libc")==0 || n.indexOf("libm")==0 || n.indexOf("libdl")==0 ||
            n.indexOf("libz")==0 || n.indexOf("liblog")==0 || n.indexOf("libandroid")==0) continue;
        out.push({name:n, base:maps[i].base.toString(), size:maps[i].size, path:maps[i].path});
    }
    send({type:"native_intel", count:out.length, mods:out});
})();
)JS";
}

std::string extractKeyScript() {
    return R"JS(
(function(){
    var targets = ["android_dlopen_ext", "dlopen", "__loader_dlopen"];
    var hooked = [];
    function hookSym(name){
        var p = Module.findExportByName(null, name);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function(args){ this.path = args[0].readCString(); },
            onLeave: function(retval){
                if (retval.isNull()) return;
                var path = this.path || "";
                if (path.indexOf(".so") < 0) return;
                var name = path.split("/").pop();
                var mod = Process.findModuleByName(name);
                if (!mod) return;
                send({type:"native_loaded", name:name, base:mod.base.toString(), size:mod.size, path:mod.path});
                try {
                    var out = "/sdcard/dump_" + name;
                    var f = new File(out, "wb");
                    f.write(mod.base.readByteArray(mod.size));
                    f.flush(); f.close();
                    send({type:"native_dumped", file:out, size:mod.size, name:name});
                } catch(e){ send({type:"native_error", msg:"write "+e.toString()}); }
            }
        });
        hooked.push(name);
    }
    for (var i=0;i<targets.length;i++) hookSym(targets[i]);
    send({type:"native_hook", hooked:hooked});
})();
)JS";
}

std::string bypassHardCaseScript() {
    return R"JS(
(function(){
    var p = Module.findExportByName(null, "ptrace");
    if (p) {
        var orig = new NativeFunction(p, "long", ["int","int","pointer","pointer"]);
        Interceptor.replace(p, new NativeCallback(function(req, pid, addr, data){
            if (req === 0 || req === 16) return -1;
            return orig(req, pid, addr, data);
        }, "long", ["int","int","pointer","pointer"]));
        send({type:"native_ptrace", msg:"ptrace hooked"});
    }
    var mods = Process.enumerateModules();
    var hits = [];
    for (var i=0;i<mods.length;i++){
        try {
            var s1 = Memory.scanSync(mods[i].base, mods[i].size, "66 72 69 64 61");
            var s2 = Memory.scanSync(mods[i].base, mods[i].size, "67 75 6d 2d 6a 73");
            if (s1.length + s2.length > 0) hits.push({name:mods[i].name, frida:s1.length, gum:s2.length});
        } catch(e){}
    }
    send({type:"native_antifrida", hits:hits});
    send({type:"native_info", msg:"anti-frida scan complete"});
})();
)JS";
}

}
