const UNHOOKABLE_FUNCTIONS = [
    "ntdll.dll!LdrInitializeThunk", // program will crash if this API is hooked.
    "ntdll.dll!DbgPrint", // program will crash if this API is hooked.
    "ntdll.dll!DbgPrintEx", // program will crash if this API is hooked.
    "ntdll.dll!vDbgPrintEx", // program will crash if this API is hooked.
    "ntdll.dll!vDbgPrintExWithPrefix", // program will crash if this API is hooked.
    "ntdll.dll!LdrUnlockLoaderLock", // program will crash if this API is hooked.
    "ntdll.dll!RtlGetEnabledExtendedFeatures", // program will crash if this API is hooked.
    "ntdll.dll!RtlImageRvaToSection", // program will crash if this API is hooked.
    "ntdll.dll!RtlUlongByteSwap", // program will crash if this API is hooked.
    "ntdll.dll!RtlUnhandledExceptionFilter", // program will crash if this API is hooked.
    "ntdll.dll!ZwContinue", // program will crash if this API is hooked.
    "ntdll.dll!NtContinue", // program will crash if this API is hooked.
]

function isUnhookableAddress(address: NativePointer) : boolean{
    let firstByte = address.readU8();
    let secondByte = address.add(1).readU8();
    if (firstByte == 0xCC && secondByte == 0xc3){
        // ntdll!DbgUserBreakPoint:
        // 00007ff9`5c5e0130 cc              int     3
        // 00007ff9`5c5e0131 c3              ret
        return true;
    }
    
    let thirdByte = address.add(2).readU8();
    if (firstByte == 0x33 && secondByte == 0xc0 && thirdByte == 0xc3){
        // ntdll!CsrIdentifyAlertableThread:
        // 00007ff9`5c5c2920 33c0            xor     eax,eax
        // 00007ff9`5c5c2922 c3              ret
        return true;
    }

    if (firstByte == 0xc2 && secondByte == 0x00 && thirdByte == 0x00){
        // ntdll!LdrQueryModuleInfoLocalLoaderLock32:
        // 00007ff9`5c5bfdc0 c20000          ret     0
        return true;
    }

    let fourthByte = address.add(3).readU8();
    if (firstByte == 0x8b && fourthByte == 0xc3){
        // ntdll!RtlNumberGenericTableElements:
        // 00007ff9`5c5c1f10 8b4124          mov     eax,dword ptr [rcx+24h]
        // 00007ff9`5c5c1f13 c3              ret
        return true;
    }

    if (firstByte == 0x0f && fourthByte == 0xc3){
        // ntdll!RtlQueryDepthSList:
        // 00007ff9`5c5aacf0 0fb701          movzx   eax,word ptr [rcx]
        // 00007ff9`5c5aacf3 c3              ret
        return true;
    }

    return false;
}

function isUnhookableFunction(exportName: string, address: NativePointer): boolean{
    if (UNHOOKABLE_FUNCTIONS.includes(exportName)){
        console.log("skipped due to explicit deny");
        return true;
    }

    let functionRange = Process.findRangeByAddress(address);
    if (!functionRange){
        console.log("skipped due to invalid range");
        return true;
    }
    if (functionRange.protection.indexOf('x') == -1){
        console.log("skipped due to not executable code");
        return true;
    }

    if (isUnhookableAddress(address)){
        console.log("skipped due to short function");
        return true;
    }

    return false;
}

function hookAllFunctionsOfModule(module: Module){
    let module_exports = module.enumerateExports();
    let counter = 0;
    module_exports.forEach(e => {
        const exportName = `${module.name}!${e.name}`;
        // 650 is OK
        // 660 is BAD
        if (counter > 650){
            return;
        }
        console.log(`hooking: ${exportName}, ${counter}`)

        if (isUnhookableFunction(exportName, e.address)){
            return;
        }

        let hook = Interceptor.attach(e.address, {
            onEnter(args) {
                console.log(`${module.name}!${e.name} called for the first time. Suspending hook`);
                hook.detach();
            }
        });
        counter++;
    });
};

function main(){
    let ntdll = Process.getModuleByName("ntdll.dll");
    let loadDllAddr = ntdll.getExportByName("LdrLoadDll");
    
    console.log("LdrLoadDll at " + loadDllAddr.toString())
    
    // let modules = Process.enumerateModules();
    // modules.forEach(m => hookAllFunctionsOfModule(m));
    hookAllFunctionsOfModule(ntdll);
    
    Interceptor.attach(loadDllAddr, {
        onEnter(args) {
            const length = args[2].readU16()
            const moduleBuffer = args[2].add(0x8).readPointer()
            const modulePath = moduleBuffer.readUtf16String(length);
            console.log(`LdrLoadDll() ModulePath="${modulePath}"`);
        }
    });    
}

main();
