/*
    Frida Xposed Bridge
    by Monkeylord, fixed by 327135569
    License: MIT
    
    Load Xposed Bridge&Modules though Frida.
    
    原理：通过Frida加载XposedBridge.jar，同时通过Frida Java Hook来实现Xposed API。随后模拟Xposed初始化，并加载插件，然后再模拟应用启动。
*/


var typeTranslation = {
    "Z": "java.lang.Boolean",
    "B": "java.lang.Byte",
    "S": "java.lang.Short",
    "I": "java.lang.Integer",
    "J": "java.lang.Long",
    "F": "java.lang.Float",
    "D": "java.lang.Double"
}

var XposedClassFactory = null
var appClassFactory = null
var pluginClassFactory = null

function mylog() {
    // console.log.apply(console, arguments)
}

function implementXposedAPI() {
    // Implement ZygoteService API
    var ZygoteService = XposedClassFactory.use("de.robv.android.xposed.services.ZygoteService")

    ZygoteService.checkFileAccess.implementation = function () {
        mylog("[API Call] checkFileAccess", " filename:", arguments[0])
        return true
    }

    ZygoteService.statFile.implementation = function () {
        mylog("[API Call] statFile", " filename:", arguments[0])
        return null
    }

    ZygoteService.readFile.overload('java.lang.String').implementation = function () {
        mylog("[API Call] readFile", " filename:", arguments[0])
        return null
    }

    // Implement XposedBridge API
    var XposedBridge = XposedClassFactory.use("de.robv.android.xposed.XposedBridge")
    XposedBridge.runtime.value = 2  // Art
    XposedBridge.hadInitErrors.implementation = function () {
        mylog("[API Call] hadInitErrors")
        return false
    }

    XposedBridge.getStartClassName.implementation = function () {
        mylog("[API Call] getStartClassName")
        // TODO
        return ""
    }

    XposedBridge.getRuntime.implementation = function () {
        mylog("[API Call] getRuntime")
        // 1 = Dalvik, 2 = Art
        return 2
    }

    XposedBridge.startsSystemServer.implementation = function () {
        mylog("[API Call] startsSystemServer")
        // TODO
        return false
    }

    XposedBridge.getXposedVersion.implementation = function () {
        mylog("[API Call] getXposedVersion")
        return 82
    }

    XposedBridge.initXResourcesNative.implementation = function () {
        mylog("[API Call] initXResourcesNative")
        // Disable Resource Hook
        // TODO: implement Resource Hook
        return false
    }

    var MethodHookParam = XposedClassFactory.use('de.robv.android.xposed.XC_MethodHook$MethodHookParam');
    var MethodHook = XposedClassFactory.use('de.robv.android.xposed.XC_MethodHook');
    var AdditionalHookInfo = XposedClassFactory.use('de.robv.android.xposed.XposedBridge$AdditionalHookInfo')

    XposedBridge.hookMethodNative.implementation = function (javaReflectedMethod, jobject, jint, javaAdditionalInfo) {
        mylog("[API Call] hookMethodNative", javaReflectedMethod.getDeclaringClass().getName(), javaReflectedMethod.getName())

        var Method = Java.use(javaReflectedMethod.$className)
        var method = Java.cast(javaReflectedMethod, Method)

        var AdditionalHookInfo = XposedClassFactory.use('de.robv.android.xposed.XposedBridge$AdditionalHookInfo')
        var additionalHookInfo = XposedClassFactory.retain(Java.cast(javaAdditionalInfo, AdditionalHookInfo))

        mylog("[API Call] hookMethodNative 1")

        // Frida中Method Hook和Constructor Hook方式不同，所以要区分
        var clazz = javaReflectedMethod.getDeclaringClass().getName()
        var mtdname = (javaReflectedMethod.$className == "java.lang.reflect.Constructor") ? "$init" : javaReflectedMethod.getName()
        var overload = method.getParameterTypes().map(function (clz) { return clz.getName() })

        mylog("[API Call] hookMethodNative", 2, mtdname, overload)

        var fridaMethod = appClassFactory.use(clazz)[mtdname].overload.apply(appClassFactory.use(clazz)[mtdname], overload)
        // mylog("[API Call] hookMethodNative", 3, 'hook', fridaMethod._p)

        fridaMethod.implementation = function () {
            // mylog(Process.getCurrentThreadId(), 'invoked', method.getName(), method.getDeclaringClass().getName())

            let isInstanceMethod = fridaMethod.type == 3    // 3 = Instance Method
            let thisObject = appClassFactory.use(clazz)
            if (isInstanceMethod)
                thisObject = this

            let retType = fridaMethod.returnType
            let _jarr = arguments
            let jarr = Object.keys(arguments).map(function (key) { return _jarr[key] })

            fridaMethod.argumentTypes.forEach(function (type, index) {
                if (type.type != "pointer") {
                    jarr[index] = Java.use(typeTranslation[type.name]).valueOf(jarr[index])
                }
                else {
                    let env = Java.vm.getEnv()
                    jarr[index] = Java.classFactory._getType("java.lang.Object").fromJni(type.toJni(jarr[index], env), env, false)
                }
            })

            try {
                let callbacks = additionalHookInfo.callbacks.value.getSnapshot()
                if (callbacks.length == 0) {
                    return fridaMethod.apply(thisObject, arguments)
                }

                var callbackLength = callbacks.length
                let paramInst = Java.retain(MethodHookParam.$new())
                paramInst.method.value = null
                paramInst.thisObject.value = isInstanceMethod ? thisObject : null
                paramInst.args.value = Java.array('java.lang.Object', jarr)

                var beforeIdx = 0
                do {
                    try {
                        var cb = Java.cast(callbacks[beforeIdx], MethodHook)
                        cb.beforeHookedMethod(paramInst)
                    }
                    catch (e) {
                        paramInst.setResult(null);
                        paramInst.returnEarly.value = false;
                        continue;
                    }
                    if (paramInst.returnEarly.value) {
                        // skip remaining "before" callbacks and corresponding "after" callbacks
                        beforeIdx++;
                        break;
                    }
                } while (++beforeIdx < callbackLength)


                if (!paramInst.returnEarly.value) {
                    try {
                        let javaR = fridaMethod.apply(thisObject, arguments)
                        if (retType.name == 'V') {
                        }
                        else if (retType.type != "pointer") {
                            javaR = Java.use(typeTranslation[retType.name]).valueOf(javaR)
                            paramInst.setResult(javaR)
                        }
                        else {
                            let retType = fridaMethod._p[4]
                            if (typeof javaR == 'string' || Array.isArray(javaR)) {
                                var f = Java.cast(retType.toJni(javaR, Java.vm.getEnv()), Java.use('java.lang.Object'))
                                paramInst.setResult(f)
                            }
                            else {
                                paramInst.setResult(javaR)
                            }
                        }
                    }
                    catch (e) {
                        console.error('Throw in original method', e.stack)
                        let r = Java.cast(e, Java.use('java.lang.Object'))
                        paramInst.setThrowable(r)
                    }
                }

                var afterIdx = beforeIdx - 1;
                do {
                    var lastResult = paramInst.getResult()
                    var lastThrowable = paramInst.getThrowable()
                    try {
                        var cb = Java.cast(callbacks[afterIdx], MethodHook)
                        cb.afterHookedMethod(paramInst)
                    }
                    catch (e) {
                        // reset to last result (ignoring what the unexpectedly exiting callback did)
                        if (lastThrowable == null) {
                            paramInst.setResult(lastResult);
                        }
                        else {
                            paramInst.setThrowable(lastThrowable);
                        }
                    }
                }
                while (--afterIdx >= 0)


                let r;
                if (paramInst.hasThrowable())
                    throw paramInst.getThrowable();
                else {
                    r = paramInst.getResult();
                }

                if (retType.name === 'V') {

                }
                else if (retType.type != 'pointer') {
                    var value
                    var basicObj = Java.cast(r, Java.use(typeTranslation[retType.name]))
                    switch (retType.name) {
                        case "Z":
                            value = basicObj.booleanValue(); break;
                        case "B":
                            value = basicObj.byteValue(); break;
                        case "S":
                            value = basicObj.shortValue(); break;
                        case "I":
                            value = basicObj.intValue(); break;
                        case "J":
                            value = basicObj.longValue(); break;
                        case "F":
                            value = basicObj.floatValue(); break;
                        case "D":
                            value = basicObj.doubleValue(); break;

                    }
                    return value
                }
                else if (retType.name.indexOf('[') === 0) {
                    return retType.fromJni(Java.classFactory._getType('java.lang.Object').toJni(r, Java.vm.getEnv()), Java.vm.getEnv(), false)
                }
                else {
                    return r
                }
            } catch (e) {
                throw e
            }
        }
    }

    XposedBridge.setObjectClassNative.implementation = function (javaObj, javaClazz) {
        mylog("[API Call] setObjectClassNative", javaObj, javaClazz)
        Java.cast(javaObj, javaClazz)
    }

    XposedBridge.dumpObjectNative.implementation = function () {
        mylog("[API Call] dumpObjectNative")
        return undefined
    }

    XposedBridge.cloneToSubclassNative.implementation = function (javaObj, javaClazz) {
        mylog("[API Call] cloneToSubclassNative", javaObj, javaClazz)
        return Java.cast(javaObj, javaClazz)
    }

    XposedBridge.removeFinalFlagNative.implementation = function () {
        mylog("[API Call] removeFinalFlagNative")
        // TODO: Remove final flag
        // This is used by Resource Hook
        // Reference: https://github.com/frida/frida-java-bridge/blob/master/lib/android.js#L1390
    }

    XposedBridge.closeFilesBeforeForkNative.implementation = function () {
        mylog("[API Call] closeFilesBeforeForkNative")
        // TODO
        // Useless outside Zygote
    }

    XposedBridge.reopenFilesAfterForkNative.implementation = function () {
        mylog("[API Call] reopenFilesAfterForkNative")
        // TODO
        // Useless outside Zygote
    }

    XposedBridge.invalidateCallersNative.implementation = function () {
        mylog("[API Call] invalidateCallersNative")
        // TODO: 
        // This is used in resource hook
    }
}

function FrameworkInit(pkgName, bridgePath, xposedPath) {
    // var ActivityThread = Java.use("android.app.ActivityThread")
    // var apkClassloader = ActivityThread.currentActivityThread().peekPackageInfo(pkgName, true).getClassLoader()

    // mylog("Current Application Classloader: ", apkClassloader)

    // 加载Xposed类
    // Java.openClassFile(bridgePath).load()
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader")

    var codeCacheDir = "/data/data/" + pkgName + "/code_cache"

    let systemClassLoader = DexClassLoader.getSystemClassLoader()
    console.log('systemClassLoader', systemClassLoader)

    var XposedCL = DexClassLoader.$new(bridgePath, codeCacheDir, null, systemClassLoader);

    XposedClassFactory = Java.ClassFactory.get(XposedCL)

    mylog("Code Cache Directory: ", codeCacheDir)
    mylog("Xposed Classloader: ", XposedCL)

    mylog("implementXposedAPI...")
    implementXposedAPI()
    mylog("implementXposedAPI...done")

    mylog("Initating Xposed Framework")

    var XposedBridge = XposedClassFactory.use("de.robv.android.xposed.XposedBridge")
    var SELinuxHelper = XposedClassFactory.use("de.robv.android.xposed.SELinuxHelper")
    var XposedInit = XposedClassFactory.use("de.robv.android.xposed.XposedInit")

    // initXResource被放弃实现，转而通过对XposedBridge.jar二次打包实现，修改了android.content.res.XResource
    // XposedBridge.initXResources()    

    XposedBridge.XPOSED_BRIDGE_VERSION.value = 82
    XposedBridge.BOOTCLASSLOADER.value = XposedCL
    XposedBridge.isZygote.value = true

    XposedInit.BASE_DIR.value = xposedPath

    SELinuxHelper.initOnce()
    SELinuxHelper.initForProcess(pkgName)

    // mylog("hookResources")
    // XposedInit.hookResources()
    // mylog("initForZygote")
    // XposedInit.initForZygote()

    mylog("Load Modules...")
    XposedInit.loadModules()
    mylog("Load Modules...done")
}

function triggerLoadPackage(thiz, appBindData, appInfo, pkgName, processName) {

    var XposedBridge = XposedClassFactory.use("de.robv.android.xposed.XposedBridge")
    var XCallback = XposedClassFactory.use("de.robv.android.xposed.callbacks.XCallback")
    var LoadPackageParam = XposedClassFactory.use("de.robv.android.xposed.callbacks.XC_LoadPackage$LoadPackageParam")

    mylog("Preparing LoadPackageParam...")
    var ActivityThread = Java.use("android.app.ActivityThread")
    var thread = ActivityThread.currentActivityThread()
    mylog(" [ProcessName]", processName)
    //mylog(appInfo.packageName.value)
    var loadedApk = thiz.getPackageInfoNoCheck(appInfo, appBindData.compatInfo.value)
    mylog(" [loadedApk]", loadedApk)
    var classLoader = loadedApk.getClassLoader()
    mylog(" [classLoader]", classLoader)

    appClassFactory = Java.ClassFactory.get(classLoader)

    var lpparam = LoadPackageParam.$new(XposedBridge.sLoadedPackageCallbacks.value)
    lpparam.packageName.value = pkgName
    lpparam.processName.value = processName
    lpparam.classLoader.value = classLoader
    lpparam.appInfo.value = loadedApk.getApplicationInfo()
    lpparam.isFirstApplication.value = true

    mylog("Preparing LoadPackageParam...done")

    mylog("Invoke handleLoadPackage...")
    XCallback.callAll(lpparam)
    mylog("Invoke handleLoadPackage...done")
}

function startBridge() {
    Java.performNow(function () {
        // Java.deoptimizeEverything()

        mylog("Hooking handleBindApplication...")
        var ActivityThread = Java.use("android.app.ActivityThread")
        ActivityThread.handleBindApplication.implementation = function (appBindData) {

            const ApplicationInfo = Java.use('android.content.pm.ApplicationInfo')
            const AppBindData = Java.use('android.app.ActivityThread$AppBindData')
            const ActivityThread = Java.use('android.app.ActivityThread')
            var activityThread = Java.cast(this, ActivityThread)
            var abd = Java.cast(appBindData, AppBindData)
            var appInfo = abd.appInfo.value

            var ai = Java.cast(appInfo, ApplicationInfo)
            var pkgName = ai.packageName.value

            mylog("Start Init Framework...")
            FrameworkInit(pkgName, "/data/local/tmp/XposedBridge.jar", "/data/local/tmp/")
            mylog("Start Init Framework...done")

            mylog("Triggering Modules Load...")
            triggerLoadPackage(activityThread, appBindData, appInfo, pkgName, abd.processName.value)

            this.handleBindApplication(appBindData)
        }

        mylog("Hooking handleBindApplication...done")
    })
}

startBridge()