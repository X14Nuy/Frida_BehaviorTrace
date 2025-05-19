// --- Configuration ---
const TARGET_MODULE_NAME = "libbaiduprotect.so";
const TARGET_FUNCTION_OFFSET = 0x409E0;
const TARGET_FUNCTION_NAME = "";
const CUSTOM_FUNCTION_OFFSETS = [0x29030, 0x290DC];  // 可根据需要添加更多自定义函数偏移

// List of libc functions to hook
const LIBC_FUNCTIONS_TO_HOOK = {
    'open': { args: ['path', 'flags', 'mode'], ret: 'fd' },
    'close': { args: ['fd'], ret: 'int' },
    'read': { args: ['fd', 'buf', 'count'], ret: 'ssize_t' },
    'write': { args: ['fd', 'buf', 'count'], ret: 'ssize_t' },
    'malloc': { args: ['size'], ret: 'pointer' },
    'free': { args: ['ptr'], ret: 'void' },
    'memcpy': { args: ['dest', 'src', 'n'], ret: 'pointer' },
    'memset': { args: ['s', 'c', 'n'], ret: 'pointer' },
    'strlen': { args: ['s'], ret: 'size_t' },
    'strcpy': { args: ['dest', 'src'], ret: 'char*' },
    'strncpy': { args: ['dest', 'src', 'n'], ret: 'char*' },
    'strcmp': { args: ['s1', 's2'], ret: 'int' },
    'sprintf': { args: ['str', 'format', '...'], ret: 'int', varargs: true },
    'sscanf': { args: ['str', 'format', '...'], ret: 'int', varargs: true },
};

const SCRIPT_START_TIME = Date.now();
let callLogBuffer = [];

if (typeof Thread.local === 'undefined') {
    Thread.local = {};
}

// Utility Functions
function getRelativeTimestamp() {
    return Date.now() - SCRIPT_START_TIME;
}

function isPrintableAscii(str) {
    return /^[\x20-\x7E]*$/.test(str);
}

function getSafeString(ptr, maxLen = 32) {
    if (ptr === null || ptr.isNull()) return "NULL_PTR";
    try {
        let s = ptr.readCString();
        if (s === null) return "NULL_C_STR";
        if (isPrintableAscii(s)) {
            return s.length > maxLen ? s.substring(0, maxLen) + "..." : s;
        } else {
            let bytes = ptr.readByteArray(8);  // 读取前 8 个字节用于 hex dump
            let hex = Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join(' ');
            return `binary_data: ${ptr} (hex: ${hex})`;
        }
    } catch (e) {
        return `${ptr} (unreadable_str)`;
    }
}

function getSafeByteArray(ptr, length) {
    if (ptr === null || ptr.isNull() || length <= 0) return "NULL/EMPTY_BYTE_ARRAY";
    try {
        let arr = ptr.readByteArray(Math.min(length, 64));
        let hex = Array.from(new Uint8Array(arr), byte => byte.toString(16).padStart(2, '0')).join('');
        return `ptr: ${ptr}, len: ${length}, hex_preview: ${hex}`;
    } catch (e) {
        return `${ptr} (unreadable byte array)`;
    }
}

function formatArgs(argsObj) {
    let formatted = [];
    for (let key in argsObj) {
        let value = argsObj[key];
        if (typeof value === 'string' && value.startsWith('0x')) {
            formatted.push(`${key}=${value}`);
        } else {
            formatted.push(`${key}="${value}"`);
        }
    }
    return formatted.join(', ');
}

function formatRetval(retval, funcMeta) {
    if (funcMeta.ret === 'void') return 'void';
    if (funcMeta.ret === 'pointer' || funcMeta.ret.endsWith('*')) {
        if (funcMeta.ret === 'char*') return getSafeString(retval);
        return retval.toString();
    }
    if (funcMeta.ret === 'int' || funcMeta.ret === 'size_t' || funcMeta.ret === 'ssize_t') {
        return retval.toInt32().toString();
    }
    return retval.toString();
}

// Logging Functions
function logCallEntry(type, funcName, argsObj, tid, isTargetFuncEntry = false) {
    if (!Thread.local[tid]) {
        Thread.local[tid] = { inTargetFunc: false, depth: 0, lastEntryWasTarget: false };
    }
    let indent = "  ".repeat(Thread.local[tid].depth);
    let timestamp = getRelativeTimestamp();
    let formattedArgs = formatArgs(argsObj);
    console.log(`${indent}[${timestamp} ms] [TID:${tid}] ${type} ENTER: ${funcName}(${formattedArgs})`);
    Thread.local[tid].depth++;
    if (isTargetFuncEntry) {
        Thread.local[tid].inTargetFunc = true;
        Thread.local[tid].lastEntryWasTarget = true;
    } else {
        Thread.local[tid].lastEntryWasTarget = false;
    }
}

function logCallExit(type, funcName, retval, tid, isTargetFuncExit = false) {
    if (!Thread.local[tid]) {
        Thread.local[tid] = { inTargetFunc: false, depth: 1, lastEntryWasTarget: false };
    }
    Thread.local[tid].depth = Math.max(0, Thread.local[tid].depth - 1);
    let indent = "  ".repeat(Thread.local[tid].depth);
    let timestamp = getRelativeTimestamp();
    console.log(`${indent}[${timestamp} ms] [TID:${tid}] ${type} EXIT: ${funcName} -> ${retval}`);
    if (isTargetFuncExit) {
        Thread.local[tid].inTargetFunc = false;
    }
}

// Hooking Functions
function hook_libc_functions() {
    for (const funcName in LIBC_FUNCTIONS_TO_HOOK) {
        const funcPtr = Module.findExportByName("libc.so", funcName);
        if (funcPtr) {
            const funcMeta = LIBC_FUNCTIONS_TO_HOOK[funcName];
            Interceptor.attach(funcPtr, {
                onEnter: function(args) {
                    const tid = Process.getCurrentThreadId();
                    if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                    this.tid = tid;
                    let parsedArgs = {};
                    if (funcMeta.args) {
                        // 对字符串进行解析
                        for (let i = 0; i < funcMeta.args.length; i++) {
                            let argName = funcMeta.args[i];
                            if (argName.includes('path') || argName.includes('str') || argName.includes('s') || argName.endsWith('s1') || argName.endsWith('s2') || argName.endsWith('name') || argName.endsWith('sig')) {
                                parsedArgs[argName] = getSafeString(args[i]);
                            } else if (argName === 'buf' && funcName === 'read') {
                                this.read_buf = args[i];
                                this.read_count = args[i+1].toInt32();
                                parsedArgs[argName] = `${args[i]} (count: ${this.read_count})`;
                            } else if (argName === 'buf' && funcName === 'write') {
                                const count = args[i+1].toInt32();
                                parsedArgs[argName] = getSafeByteArray(args[i], count);
                            } else {
                                parsedArgs[argName] = args[i].toString();
                            }
                        }
                    }
                    if (funcMeta.varargs) parsedArgs['...'] = 'VARARGS_NOT_FULLY_PARSED';
                    logCallEntry("LIBC", funcName, parsedArgs, tid);
                },
                onLeave: function(retval) {
                    const tid = this.tid;
                    if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                    let retStr = formatRetval(retval, funcMeta);
                    if (funcName === 'read' && retval.toInt32() > 0) {
                        retStr += ` (buf_content_preview: ${getSafeByteArray(this.read_buf, retval.toInt32())})`;
                    }
                    logCallExit("LIBC", funcName, retStr, tid);
                }
            });
        } else {
            console.warn(`[!] Libc function not found: ${funcName}`);
        }
    }
    console.log("[+] Libc hooks (conditional) prepared.");
}

function hook_custom_functions(module) {
    CUSTOM_FUNCTION_OFFSETS.forEach(offset => {
        let funcAddr = module.base.add(offset);
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallEntry("CUSTOM", `sub_${offset.toString(16)}`, {}, tid);
            },
            onLeave: function(retval) {
                const tid = Process.getCurrentThreadId();
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("CUSTOM", `sub_${offset.toString(16)}`, retval.toString(), tid);
            }
        });
        console.log(`[+] Hooked custom function at offset 0x${offset.toString(16)}`);
    });
}

function hook_libart() {
    var symbols = Module.enumerateSymbolsSync("libart.so");
    var addrGetStringUTFChars = null;
    var addrNewStringUTF = null;
    var addrFindClass = null;
    var addrGetMethodID = null;
    var addrGetStaticMethodID = null;
    var addrCallObjectMethod = null;
    var addrRegisterNatives = null;
    var addrExceptionCheck = null;

    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("art") >= 0 && symbol.name.indexOf("JNI") >= 0 && symbol.name.indexOf("CheckJNI") < 0) {
            if (symbol.name.indexOf("GetStringUTFChars") >= 0 && !addrGetStringUTFChars) {
                addrGetStringUTFChars = symbol.address;
                console.log("GetStringUTFChars is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("NewStringUTF") >= 0 && !addrNewStringUTF) {
                addrNewStringUTF = symbol.address;
                console.log("NewStringUTF is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("FindClass") >= 0 && !addrFindClass) {
                addrFindClass = symbol.address;
                console.log("FindClass is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("GetMethodID") >= 0 && !addrGetMethodID && !symbol.name.includes("GetStaticMethodID")) {
                addrGetMethodID = symbol.address;
                console.log("GetMethodID is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("GetStaticMethodID") >= 0 && !addrGetStaticMethodID) {
                addrGetStaticMethodID = symbol.address;
                console.log("GetStaticMethodID is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("CallObjectMethod") >= 0 && !addrCallObjectMethod) {
                addrCallObjectMethod = symbol.address;
                console.log("CallObjectMethod is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("RegisterNatives") >= 0 && !addrRegisterNatives) {
                addrRegisterNatives = symbol.address;
                console.log("RegisterNatives is at ", symbol.address, symbol.name);
            } else if (symbol.name.indexOf("ExceptionCheck") >= 0 && !addrExceptionCheck) {
                addrExceptionCheck = symbol.address;
                console.log("ExceptionCheck is at ", symbol.address, symbol.name);
            }
        }
    }

    if (addrGetStringUTFChars) {
        Interceptor.attach(addrGetStringUTFChars, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                this.tid = tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                let parsedArgs = { 'jstring_str': args[1].toString(), 'isCopy_ptr': args[2].toString() };
                logCallEntry("JNI", "GetStringUTFChars", parsedArgs, tid);
            },
            onLeave: function(retval) {
                const tid = this.tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("JNI", "GetStringUTFChars", getSafeString(retval), tid);
            }
        });
    }

    if (addrNewStringUTF) {
        Interceptor.attach(addrNewStringUTF, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                this.tid = tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                let parsedArgs = { 'char*_bytes': getSafeString(args[1]) };
                logCallEntry("JNI", "NewStringUTF", parsedArgs, tid);
            },
            onLeave: function(retval) {
                const tid = this.tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("JNI", "NewStringUTF", retval.toString(), tid);
            }
        });
    }

    if (addrFindClass) {
        Interceptor.attach(addrFindClass, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                this.tid = tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                let parsedArgs = { 'char*_name': getSafeString(args[1]) };
                logCallEntry("JNI", "FindClass", parsedArgs, tid);
            },
            onLeave: function(retval) {
                const tid = this.tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("JNI", "FindClass", retval.toString(), tid);
            }
        });
    }

    if (addrGetMethodID) {
        Interceptor.attach(addrGetMethodID, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                this.tid = tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                let parsedArgs = {
                    'jclass_clazz': args[1].toString(),
                    'char*_name': getSafeString(args[2]),
                    'char*_sig': getSafeString(args[3])
                };
                logCallEntry("JNI", "GetMethodID", parsedArgs, tid);
            },
            onLeave: function(retval) {
                const tid = this.tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("JNI", "GetMethodID", retval.toString(), tid);
            }
        });
    }

    if (addrGetStaticMethodID) {
        Interceptor.attach(addrGetStaticMethodID, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                this.tid = tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                let parsedArgs = {
                    'jclass_clazz': args[1].toString(),
                    'char*_name': getSafeString(args[2]),
                    'char*_sig': getSafeString(args[3])
                };
                logCallEntry("JNI", "GetStaticMethodID", parsedArgs, tid);
            },
            onLeave: function(retval) {
                const tid = this.tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("JNI", "GetStaticMethodID", retval.toString(), tid);
            }
        });
    }

    if (addrCallObjectMethod) {
        Interceptor.attach(addrCallObjectMethod, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                this.tid = tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                let parsedArgs = {
                    'jobject_obj': args[1].toString(),
                    'jmethodID_method': args[2].toString(),
                    '...': 'VARARGS_NOT_FULLY_PARSED'
                };
                logCallEntry("JNI", "CallObjectMethod", parsedArgs, tid);
            },
            onLeave: function(retval) {
                const tid = this.tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("JNI", "CallObjectMethod", retval.toString(), tid);
            }
        });
    }

    if (addrRegisterNatives) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                this.tid = tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                let parsedArgs = {
                    'jclass_clazz': args[1].toString(),
                    'methods_array_ptr': args[2].toString(),
                    'jint_nMethods': args[3].toString()
                };
                logCallEntry("JNI", "RegisterNatives", parsedArgs, tid);
            },
            onLeave: function(retval) {
                const tid = this.tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("JNI", "RegisterNatives", retval.toString(), tid);
            }
        });
    }

    if (addrExceptionCheck) {
        Interceptor.attach(addrExceptionCheck, {
            onEnter: function(args) {
                const tid = Process.getCurrentThreadId();
                this.tid = tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                let parsedArgs = {};
                logCallEntry("JNI", "ExceptionCheck", parsedArgs, tid);
            },
            onLeave: function(retval) {
                const tid = this.tid;
                if (!Thread.local[tid] || !Thread.local[tid].inTargetFunc) return;
                logCallExit("JNI", "ExceptionCheck", retval.toString(), tid);
            }
        });
    }

    console.log("[+] Libart JNI hooks (conditional) prepared.");
}

function hook_main_target_function_for_tracing() {
    let targetAddress;
    const module = Process.findModuleByName(TARGET_MODULE_NAME);
    if (!module) {
        console.warn(`[!] Module ${TARGET_MODULE_NAME} not found. Waiting...`);
        setTimeout(hook_main_target_function_for_tracing, 2000);
        return;
    }
    if (TARGET_FUNCTION_OFFSET && typeof TARGET_FUNCTION_OFFSET === 'number') {
        targetAddress = module.base.add(TARGET_FUNCTION_OFFSET);
    } else if (TARGET_FUNCTION_NAME && typeof TARGET_FUNCTION_NAME === 'string') {
        targetAddress = module.findExportByName(TARGET_FUNCTION_NAME) || null;
        if (!targetAddress) {
            const symbols = module.enumerateSymbols();
            const foundSymbol = symbols.find(sym => sym.name === TARGET_FUNCTION_NAME);
            if (foundSymbol) targetAddress = foundSymbol.address;
        }
    }
    if (!targetAddress) {
        console.error(`[!] Could not find target function (offset: ${TARGET_FUNCTION_OFFSET}, name: ${TARGET_FUNCTION_NAME}) in ${TARGET_MODULE_NAME}.`);
        return;
    }
    console.log(`[+] Target function: ${targetAddress} in ${TARGET_MODULE_NAME}`);
    Interceptor.attach(targetAddress, {
        onEnter: function(args) {
            const tid = Process.getCurrentThreadId();
            let targetArgs = {};
            logCallEntry("TARGET", (TARGET_FUNCTION_NAME || `offset_0x${TARGET_FUNCTION_OFFSET.toString(16)}`), targetArgs, tid, true);
            hook_libc_functions();
            hook_libart();
            hook_custom_functions(module);  // 钩住自定义函数
        },
        onLeave: function(retval) {
            const tid = Process.getCurrentThreadId();
            let retStr = retval.toString();
            logCallExit("TARGET", (TARGET_FUNCTION_NAME || `offset_0x${TARGET_FUNCTION_OFFSET.toString(16)}`), retStr, tid, true);
        }
    });
    console.log(`[+] Hooked target function: ${TARGET_FUNCTION_NAME || `offset_0x${TARGET_FUNCTION_OFFSET.toString(16)}`}`);
}

var offset = 0x88060;
var module_size = 0;
var module_name = "libbaiduprotect.so";
var base_addr = null;
var empty_func = new NativeCallback(function() { return 0; }, 'int', ['pointer']);

function hook_linker_call_constructors() {
    let linker_base_addr = Module.getBaseAddress('linker64');
    let offset_call_constructors = 0x51BA8;
    let call_constructors_addr = linker_base_addr.add(offset_call_constructors);
    console.log(`[+] Attempting to hook linker's call_constructors at ${call_constructors_addr}`);
    let listener = Interceptor.attach(call_constructors_addr, {
        onEnter: function(args) {
            console.log('[linker] Call_Constructors onEnter');
            let secmodule = Process.findModuleByName(module_name);
            if (secmodule != null && base_addr == null) {
                module_size = secmodule.size;
                base_addr = secmodule.base;
                console.log(`${module_name} base: ${base_addr}, size: ${module_size}`);
                hook_target_func(base_addr);
                listener.detach();
                console.log('[linker] Detached from call_constructors.');
            }
        }
    });
}

function hook_target_func(current_base_addr) {
    let intermediate_target_addr = current_base_addr.add(offset);
    console.log(`[+] Attaching to intermediate target function at ${intermediate_target_addr}`);
    let listener = Interceptor.attach(intermediate_target_addr, {
        onEnter: function(args) {
            console.log(`[+] Intermediate target function at ${intermediate_target_addr} entered.`);
        },
        onLeave: function(retval) {
            console.log(`[+] Intermediate target function at ${intermediate_target_addr} exited.`);
            hook_pthread_create();
            hook_main_target_function_for_tracing();
            listener.detach();
            console.log(`[+] Detached from intermediate target function at ${intermediate_target_addr}.`);
        }
    });
}

function hook_pthread_create() {
    let pthread_create_addr = Module.findExportByName(null, "pthread_create");
    if (!pthread_create_addr) {
        console.error("[!] Could not find pthread_create export.");
        return;
    }
    console.log(`[+] Hooking pthread_create at ${pthread_create_addr}`);
    Interceptor.attach(pthread_create_addr, {
        onEnter: function(args) {
            let func_addr = args[2];
            if (!base_addr) return;
            let target_thread_func_offset = 0x3E9F0;
            let specific_thread_func_addr = base_addr.add(target_thread_func_offset);
            if (func_addr.equals(specific_thread_func_addr)) {
                console.log(`[pthread_create] Intercepted specific thread (start_routine: ${func_addr}). Replacing with empty function.`);
                args[2] = empty_func;
            }
        }
    });
}

function main() {
    console.log("[*] Frida script starting...");
    hook_linker_call_constructors();
}

rpc.exports = {
    getCallLog: function() { return callLogBuffer; },
    clearCallLog: function() { callLogBuffer = []; console.log("[*] Call log buffer cleared via RPC."); }
};

setImmediate(main);