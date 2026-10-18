#include "../modules.h"

namespace cocos {

bool detect() { return true; }

std::string dumpIntelScript() {
    return R"JS(
(function(){
    var libs = ["libcocos2djs.so","libcocos2d.so","libcocos.so","libCocos2d-x.so"];
    var mod = null;
    for (var i=0;i<libs.length;i++){ var m = Process.findModuleByName(libs[i]); if(m){mod=m;break;} }
    if(!mod){ send({type:"cocos_error",msg:"lib not found"}); return; }
    send({type:"cocos_intel", name:mod.name, base:mod.base.toString(), size:mod.size, path:mod.path});
    var exports = mod.enumerateExports();
    var hits = [];
    for (var j=0;j<exports.length;j++){
        var n = exports[j].name;
        if (n.indexOf("xxtea")>=0 || n.indexOf("jsb_set_xxtea")>=0 || (n.indexOf("jsb_")>=0 && n.indexOf("key")>=0)) {
            hits.push({name:n, addr:exports[j].address.toString()});
        }
    }
    send({type:"cocos_exports", hits:hits});
})();
)JS";
}

std::string extractKeyScript() {
    return R"JS(
(function(){
    function toHex(ptr, len){
        var s=""; for(var i=0;i<len;i++){ var b=ptr.add(i).readU8(); s+=("0"+b.toString(16)).slice(-2);} return s;
    }
    var libs = ["libcocos2djs.so","libcocos2d.so","libcocos.so","libCocos2d-x.so"];
    var mod = null;
    for (var i=0;i<libs.length;i++){ var m = Process.findModuleByName(libs[i]); if(m){mod=m;break;} }
    if(!mod){ send({type:"cocos_error",msg:"lib not found"}); return; }
    var dec = mod.findExportByName("xxtea_decrypt");
    if (dec) {
        Interceptor.attach(dec, {
            onEnter: function(args){
                try {
                    var keyPtr = args[2];
                    var keyLen = args[3].toInt32();
                    if (keyLen > 0 && keyLen < 256) {
                        send({type:"cocos_xxtea_key", via:"xxtea_decrypt",
                              ptr:keyPtr.toString(), key_len:keyLen, hex:toHex(keyPtr,keyLen)});
                    }
                } catch(e){ send({type:"cocos_error",msg:e.toString()}); }
            }
        });
        send({type:"cocos_hook", msg:"xxtea_decrypt hooked"});
    } else {
        send({type:"cocos_info", msg:"xxtea_decrypt export not found"});
    }
    var setKey = mod.findExportByName("jsb_set_xxtea_key");
    if (setKey) {
        Interceptor.attach(setKey, {
            onEnter: function(args){
                try {
                    var p = args[0];
                    send({type:"cocos_xxtea_key", via:"jsb_set_xxtea_key",
                          ptr:p.toString(), hex:toHex(p,64), hint:"64B around ptr, may be XOR/assembled"});
                } catch(e){ send({type:"cocos_error",msg:e.toString()}); }
            }
        });
        send({type:"cocos_hook", msg:"jsb_set_xxtea_key hooked"});
    } else {
        send({type:"cocos_info", msg:"jsb_set_xxtea_key export not found"});
    }
})();
)JS";
}

std::string bypassHardCaseScript() {
    return R"JS(
(function(){
    var libs = ["libcocos2djs.so","libcocos2d.so","libcocos.so"];
    var mod = null;
    for (var i=0;i<libs.length;i++){ var m = Process.findModuleByName(libs[i]); if(m){mod=m;break;} }
    if(!mod){ send({type:"cocos_error",msg:"lib not found"}); return; }
    var found = [];
    var pat = "63 6f 63 6f 73";
    try {
        var matches = Memory.scanSync(mod.base, mod.size, pat);
        for (var j=0;j<Math.min(matches.length,32);j++){
            var a = matches[j].address;
            var before = a.sub(32);
            try {
                var hx = "";
                var buf = before.readByteArray(64);
                var u8 = new Uint8Array(buf);
                for (var k=0;k<u8.length;k++) hx += ("0"+u8[k].toString(16)).slice(-2);
                found.push({at:a.toString(), around:hx});
            } catch(e){}
        }
    } catch(e){ send({type:"cocos_error",msg:"scan "+e.toString()}); }
    send({type:"cocos_xor_candidates", count:found.length, items:found});
})();
)JS";
}

}
