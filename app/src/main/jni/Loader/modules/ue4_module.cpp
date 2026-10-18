#include "../modules.h"

namespace ue4 {

bool detect() { return true; }

std::string dumpIntelScript() {
    return R"JS(
(function(){
    var m = Process.findModuleByName("libUE4.so") || Process.findModuleByName("libUnreal.so");
    if (!m) { send({type:"ue4_error", msg:"UE4 lib not found"}); return; }
    send({type:"ue4_intel", name:m.name, base:m.base.toString(), size:m.size, path:m.path});
    var peCandidates = ["ProcessEvent","_ZN7UObject12ProcessEventEP9UFunctionPv","_ZN7UObject12ProcessEventEP9UFunctionPvS1_"];
    var pe = null;
    for (var i=0;i<peCandidates.length;i++){
        var p = m.findExportByName(peCandidates[i]);
        if (p) { pe = p; send({type:"ue4_info", msg:"ProcessEvent@"+p.toString()}); break; }
    }
    if (!pe) send({type:"ue4_warn", msg:"ProcessEvent export not found"});
    var ranges = m.enumerateRanges("rw-");
    var candidates = [];
    for (var r=0; r<ranges.length && candidates.length<8; r++){
        try {
            var cnt = Math.min(ranges[r].size, 0x20000) / Process.pointerSize;
            for (var k=0;k<cnt;k++){
                var p = ranges[r].base.add(k*Process.pointerSize).readPointer();
                if (p.isNull()) continue;
                var m2 = Process.findRangeByAddress(p);
                if (m2 && (m2.protection.indexOf("rw")>=0)) {
                    candidates.push(ranges[r].base.add(k*Process.pointerSize).toString());
                    if (candidates.length>=8) break;
                }
            }
        } catch(e){}
    }
    send({type:"ue4_guobject_candidates", count:candidates.length, addrs:candidates});
})();
)JS";
}

std::string extractKeyScript() {
    return R"JS(
(function(){
    var m = Process.findModuleByName("libUE4.so") || Process.findModuleByName("libUnreal.so");
    if (!m) { send({type:"ue4_error", msg:"UE4 lib not found"}); return; }
    var cands = ["_ZN12FFileHelper16LoadFileToStringEP7FStringPKcP14IFileManager","FMemory::Memcpy"];
    var hits = [];
    for (var i=0;i<cands.length;i++){
        var p = m.findExportByName(cands[i]);
        if (p) hits.push({name:cands[i], addr:p.toString()});
    }
    send({type:"ue4_archive_hooks", hits:hits});
})();
)JS";
}

std::string bypassHardCaseScript() {
    return R"JS(
(function(){
    var m = Process.findModuleByName("libUE4.so") || Process.findModuleByName("libUnreal.so");
    if (!m) { send({type:"ue4_error", msg:"UE4 lib not found"}); return; }
    try {
        var s = Memory.scanSync(m.base, m.size, "66 72 69 64 61");
        if (s.length) send({type:"ue4_antifrida", hits:s.length});
    } catch(e){}
    var pe = m.findExportByName("ProcessEvent") || m.findExportByName("_ZN7UObject12ProcessEventEP9UFunctionPv");
    if (pe) {
        var log = [];
        Interceptor.attach(pe, { onEnter: function(args){
            if (log.length < 200) log.push({self:args[0].toString(), func:args[1].toString()});
        }});
        send({type:"ue4_pe_hooked", msg:"sampling"});
        setInterval(function(){ if (log.length){ send({type:"ue4_pe_samples", samples:log}); log = []; } }, 5000);
    } else {
        send({type:"ue4_warn", msg:"ProcessEvent not found"});
    }
})();
)JS";
}

}
