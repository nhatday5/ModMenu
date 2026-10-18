#include "../modules.h"

namespace unity {

bool detect() { return true; }

std::string dumpIntelScript() {
    return R"JS(
(function(){
    var m = Process.findModuleByName("libil2cpp.so");
    if (!m) { send({type:"unity_error", msg:"libil2cpp.so not found"}); return; }
    send({type:"unity_intel", base:m.base.toString(), size:m.size, path:m.path});
    function F(n){ var p = m.findExportByName(n); if (!p) throw new Error("missing export: "+n); return p; }
    try {
        var domain_get         = new NativeFunction(F("il2cpp_domain_get"), "pointer", []);
        var domain_get_asm     = new NativeFunction(F("il2cpp_domain_get_assemblies"), "pointer", ["pointer","pointer"]);
        var asm_get_image      = new NativeFunction(F("il2cpp_assembly_get_image"), "pointer", ["pointer"]);
        var img_get_class_cnt  = new NativeFunction(F("il2cpp_image_get_class_count"), "uint32", ["pointer"]);
        var img_get_class      = new NativeFunction(F("il2cpp_image_get_class"), "pointer", ["pointer","uint32"]);
        var cls_get_name       = new NativeFunction(F("il2cpp_class_get_name"), "pointer", ["pointer"]);
        var cls_get_ns         = new NativeFunction(F("il2cpp_class_get_namespace"), "pointer", ["pointer"]);
        var domain = domain_get();
        var cntPtr = Memory.alloc(4);
        var asms = domain_get_asm(domain, cntPtr);
        var n = cntPtr.readU32();
        send({type:"unity_info", msg:"assemblies="+n});
        var classes = [];
        for (var i=0;i<n;i++){
            var asm = asms.add(i*Process.pointerSize).readPointer();
            if (asm.isNull()) continue;
            var img = asm_get_image(asm);
            if (img.isNull()) continue;
            var cc = img_get_class_cnt(img);
            for (var j=0;j<cc;j++){
                var cls = img_get_class(img, j);
                if (cls.isNull()) continue;
                var np = cls_get_name(cls);
                var nsp = cls_get_ns(cls);
                if (np.isNull()) continue;
                var name = np.readCString();
                var ns = nsp.isNull() ? "" : nsp.readCString();
                classes.push(ns + "::" + name);
                if (classes.length >= 5000) break;
            }
            if (classes.length >= 5000) break;
        }
        send({type:"unity_classes", count:classes.length, classes:classes});
    } catch(e) { send({type:"unity_error", msg:e.toString()}); }
})();
)JS";
}

std::string extractKeyScript() {
    return R"JS(
(function(){
    var m = Process.findModuleByName("libil2cpp.so");
    if (!m) { send({type:"unity_error", msg:"libil2cpp.so not found"}); return; }
    try {
        var dget = new NativeFunction(m.findExportByName("il2cpp_domain_get"), "pointer", []);
        var dga  = new NativeFunction(m.findExportByName("il2cpp_domain_get_assemblies"), "pointer", ["pointer","pointer"]);
        var agi  = new NativeFunction(m.findExportByName("il2cpp_assembly_get_image"), "pointer", ["pointer"]);
        var domain = dget();
        var cnt = Memory.alloc(4);
        var asms = dga(domain, cnt);
        var n = cnt.readU32();
        var out = [];
        for (var i=0;i<n;i++){
            var asm = asms.add(i*Process.pointerSize).readPointer();
            if (asm.isNull()) continue;
            var img = agi(asm);
            out.push({idx:i, image:img.toString()});
        }
        send({type:"unity_assets", count:out.length, images:out});
    } catch(e){ send({type:"unity_error", msg:e.toString()}); }
})();
)JS";
}

std::string bypassHardCaseScript() {
    return R"JS(
(function(){
    var m = Process.findModuleByName("libil2cpp.so");
    if (!m) { send({type:"unity_error", msg:"libil2cpp.so not found"}); return; }
    var init = m.findExportByName("il2cpp_init");
    if (init) {
        Interceptor.attach(init, { onLeave: function(){ send({type:"unity_info", msg:"il2cpp_init returned"}); } });
    }
    try {
        var s1 = Memory.scanSync(m.base, m.size, "66 72 69 64 61");
        send({type:"unity_antifrida", hits:s1.length});
    } catch(e){}
    send({type:"unity_info", msg:"hard-case ready"});
})();
)JS";
}

}
