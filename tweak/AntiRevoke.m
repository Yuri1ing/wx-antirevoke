//
//  AntiRevoke.m — 微信防撤回（iOS / 非越狱注入版）
//
//  ── 设计原则：稳定第一 ───────────────────────────────────────────────
//  1. 零第三方依赖。只用 ObjC runtime 自带的 method_setImplementation，
//     不链接 CydiaSubstrate / ellekit / fishhook。
//     非越狱设备上根本没有 substrate，链接它必然加载失败——这是老 tweak 闪退的头号原因。
//
//  2. 只替换「目标类自己定义」的方法（遍历 class_copyMethodList 精确匹配），
//     绝不通过父类命中，避免污染继承链上的其它逻辑。
//
//  3. 按原方法的真实返回类型选择桩函数。
//     如果原方法返回 BOOL 而我们用 void 桩，调用方会读到寄存器里的垃圾值，
//     可能走进完全错误的逻辑分支。所以这里先读 method_getTypeEncoding，
//     返回类型不认识就干脆放弃 hook。
//
//  4. 只 hook 方法名里确实含 revoke/recall 的方法，双保险，防止误伤。
//
//  5. 任何一步失败都只记日志并跳过，绝不抛异常、绝不 abort。
//
//  6. 只在微信主进程生效（校验 bundle id）。
//
//  7. 类可能延迟注册，分多轮延迟重试，而不是只扫一次。
//
//  ── 撤回拦截原理 ───────────────────────────────────────────────────
//  微信收到「撤回」系统消息后，由 MessageRevokeMgr 处理：
//  替换本地原消息、插入一条「XXX撤回了一条消息」的提示。
//  我们不调用原实现，于是原消息原样保留，会话里也不会出现撤回提示。
//
//  这一条链路是对微信 8.0.75 真实 IPA 离线分析得出的（读 Mach-O 的
//  __objc_classlist / class_ro_t），不是沿用手册。详见候选表上方的注释。
//
//  （老项目 itenfay/WeChat_tweak 的做法是「不调原实现 + 用 AddLocalMsg: 伪造一条
//   提示消息」。那样要碰 CMessageWrap / AddLocalMsg: 等内部 API，版本一变就容易崩，
//    且不属于「只做防撤回」的范围，故本项目不采用。）
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <ctype.h>
#import <string.h>
#import <stdlib.h>
#import <stdarg.h>

// ===========================================================================
#pragma mark - 版本与开关

#define WXAR_VERSION      "1.0.0"
#define WXAR_TARGET_BID   "com.tencent.xin"

// 日志文件超过这个大小就清空重建，避免无限增长
#define WXAR_MAX_LOG_SIZE (512 * 1024)

// 延迟重试的轮次（秒）。微信的类大多在启动阶段就注册好了，
// 留几轮是为了兜底那些懒加载的控制器。
static const double kRetryDelays[] = {0.0, 1.0, 3.0, 6.0, 12.0, 20.0};

// ===========================================================================
#pragma mark - 日志

static NSString *gLogPath = nil;
static NSLock   *gLogLock = nil;

static void WXARLogInit(void) {
    if (gLogLock) return;
    gLogLock = [[NSLock alloc] init];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (docs) {
        gLogPath = [docs stringByAppendingPathComponent:@"wxantirevoke.log"];
    }
}

static void WXARLog(NSString *fmt, ...) {
    WXARLogInit();
    va_list ap;
    va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSLog(@"[anti-revoke] %@", body);

    if (!gLogPath) return;
    NSString *line = [NSString stringWithFormat:@"[anti-revoke] %@\n", body];

    [gLogLock lock];
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSDictionary *attr = [fm attributesOfItemAtPath:gLogPath error:NULL];
        if (attr && [attr fileSize] > WXAR_MAX_LOG_SIZE) {
            [fm removeItemAtPath:gLogPath error:NULL];
        }
        if (![fm fileExistsAtPath:gLogPath]) {
            [line writeToFile:gLogPath atomically:YES
                     encoding:NSUTF8StringEncoding error:NULL];
        } else {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
            if (fh) {
                [fh seekToEndOfFile];
                [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                [fh closeFile];
            }
        }
    } @catch (NSException *e) {
        // 记日志失败绝不影响主流程
    } @finally {
        [gLogLock unlock];
    }
}

// ===========================================================================
#pragma mark - Hook 引擎

typedef struct {
    Class  cls;
    SEL    sel;
    IMP    original;
} WXARHookRecord;

static WXARHookRecord gHooks[32];
static int            gHookCount = 0;

/// 判断某个方法是不是「由这个类自己定义」的（而不是从父类继承的）。
/// 这样 method_setImplementation 只会影响目标类。
static Method WXAROwnMethod(Class cls, SEL sel) {
    unsigned int count = 0;
    Method *list = class_copyMethodList(cls, &count);
    if (!list) return NULL;
    Method found = NULL;
    for (unsigned int i = 0; i < count; i++) {
        if (method_getName(list[i]) == sel) {
            found = list[i];
            break;
        }
    }
    free(list);
    return found;
}

// ---- 桩函数：按原方法返回类型选用 -------------------------------------

static void WXARNoteHit(id self, SEL _cmd, id arg) {
    const char *argCls = "nil";
    if (arg) {
        // 用 C 函数取类名，比发消息更轻、更不容易出意外
        argCls = object_getClassName(arg);
    }
    WXARLog(@"🛡 已拦截撤回  %@ -%@   参数类型=%s",
            NSStringFromClass([self class]), NSStringFromSelector(_cmd), argCls);
}

static void  wxar_stub_void(id self, SEL _cmd, id a1) { WXARNoteHit(self, _cmd, a1); }
static BOOL  wxar_stub_bool(id self, SEL _cmd, id a1) { WXARNoteHit(self, _cmd, a1); return NO; }
static id    wxar_stub_obj (id self, SEL _cmd, id a1) { WXARNoteHit(self, _cmd, a1); return nil; }
static long  wxar_stub_int (id self, SEL _cmd, id a1) { WXARNoteHit(self, _cmd, a1); return 0; }

typedef NS_ENUM(NSInteger, WXARStub) {
    WXARStubUnsupported = 0,
    WXARStubVoid,
    WXARStubBool,
    WXARStubObj,
    WXARStubInt,
};

/// 只解析返回类型（encoding 的第一个字符），不碰参数列表——参数解析容易出错，
/// 而我们的桩本来就忽略所有参数，不需要知道参数个数。
static WXARStub WXARStubForEncoding(const char *types) {
    if (!types || !*types) return WXARStubUnsupported;
    const char *p = types;
    // 跳过返回类型的修饰符
    while (*p && strchr("rnNoORV", *p)) p++;
    switch (*p) {
        case 'v': return WXARStubVoid;
        case 'c': case 'C': case 'B': return WXARStubBool;
        case 'i': case 'I': case 's': case 'S':
        case 'l': case 'L': case 'q': case 'Q': return WXARStubInt;
        case '@': case '#': return WXARStubObj;
        default:  return WXARStubUnsupported;   // 不认识的返回类型，宁可不 hook
    }
}

static IMP WXARImpForStub(WXARStub stub) {
    switch (stub) {
        case WXARStubVoid: return (IMP)wxar_stub_void;
        case WXARStubBool: return (IMP)wxar_stub_bool;
        case WXARStubObj:  return (IMP)wxar_stub_obj;
        case WXARStubInt:  return (IMP)wxar_stub_int;
        default:           return NULL;
    }
}

static BOOL WXARContainsRevokeWord(const char *s) {
    if (!s || !*s) return NO;
    char buf[256];
    size_t n = strlen(s);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    for (size_t i = 0; i < n; i++) buf[i] = (char)tolower((unsigned char)s[i]);
    buf[n] = '\0';
    return strstr(buf, "revoke") != NULL || strstr(buf, "recall") != NULL;
}

/// 安全的实例方法替换。返回 YES 表示替换成功。
static BOOL WXARSwizzle(NSString *clsName, NSString *selName) {
    Class cls = objc_getClass(clsName.UTF8String);
    if (!cls) return NO;                       // 类不存在是常态（跨版本），不刷屏

    SEL sel = NSSelectorFromString(selName);
    Method m = WXAROwnMethod(cls, sel);
    if (!m) return NO;

    // 双保险：方法名里必须真的含 revoke / recall
    const char *selCStr = sel_getName(sel);
    if (!WXARContainsRevokeWord(selCStr)) {
        WXARLog(@"拒绝 hook %@ -%@：方法名不含 revoke/recall", clsName, selName);
        return NO;
    }

    // 已经 hook 过就不重复
    for (int i = 0; i < gHookCount; i++) {
        if (gHooks[i].cls == cls && gHooks[i].sel == sel) return YES;
    }
    if (gHookCount >= (int)(sizeof(gHooks) / sizeof(gHooks[0]))) {
        WXARLog(@"hook 表已满，跳过 %@ -%@", clsName, selName);
        return NO;
    }

    const char *types = method_getTypeEncoding(m);
    WXARStub stub = WXARStubForEncoding(types);
    IMP newImp = WXARImpForStub(stub);
    if (!newImp) {
        WXARLog(@"放弃 %@ -%@：返回类型无法识别 [%s]", clsName, selName,
                types ? types : "?");
        return NO;
    }

    IMP original = method_setImplementation(m, newImp);
    if (!original) {
        WXARLog(@"替换失败 %@ -%@", clsName, selName);
        return NO;
    }

    WXARHookRecord *rec = &gHooks[gHookCount++];
    rec->cls = cls;
    rec->sel = sel;
    rec->original = original;

    WXARLog(@"✅ 已拦截 %@ -%@   [%s]", clsName, selName, types ? types : "?");
    return YES;
}

// ===========================================================================
#pragma mark - 候选表

//
// 下表全部来自对「微信 8.0.75 真实 IPA」的离线解析结果
// （tools/analyze_wechat.py 直接读 Mach-O 的 __objc_classlist / class_ro_t，
//   不是从网上抄的旧资料）。验证命令：
//     python tools/query_classes.py build/classes-8.0.75.txt MessageRevokeMgr
//
// ⚠️ 重要事实：坊间流传最广的 `CMessageMgr -onRevokeMsg:`（也是唯一有公开
//    iOS 源码佐证的那个）在 8.0.75 里**并不存在**。CMessageMgr 类还在，
//    有 348 个方法，但撤回相关的是 RevokeMsg:MsgWrap:Counter: 之类的另一个体系。
//
// 8.0.75 实测存在的撤回入口：
//   MessageRevokeMgr      -onRevokeMsg:            单条撤回通知入口
//   MessageBatchRevokeMgr -onRevokeMsg:            批量/连续撤回入口
//   MessageRevokeMgr      -replaceRevokedMsg:      执行「把原消息换成撤回提示」
//   MessageRevokeMgr      -batchReplaceRevokedMsg: 批量版
//
// 每个候选都必须通过「类已注册 + 本类定义该方法 + 方法名含 revoke/recall
// + 返回类型可识别」四重校验才会生效，任何一条不满足就静默跳过。
//
typedef struct {
    const char *cls;
    const char *sel;
} WXARCandidate;

static WXARCandidate kCandidates[] = {
    // ===== 8.0.75 实测存在：撤回入口（主拦截点）=====
    {"MessageRevokeMgr",                "onRevokeMsg:"},
    {"MessageBatchRevokeMgr",           "onRevokeMsg:"},

    // ===== 8.0.75 实测存在：真正执行替换的动作（冗余兜底）=====
    // 副作用提示：这两条如果生效，你自己主动撤回消息时，本地也会保留原文
    //（相当于「自己也防撤回」）。如果不想要这个效果，把下面两行注释掉再重新编译即可。
    {"MessageRevokeMgr",                "replaceRevokedMsg:"},
    {"MessageRevokeMgr",                "batchReplaceRevokedMsg:"},

    // ===== 跨版本兜底：8.0.75 里不存在，为其它/将来版本保留 =====
    {"CMessageMgr",                     "onRevokeMsg:"},
    {"CMessageMgr",                     "HandleRevokeMsg:"},
    {"MessageLogicController",          "onRevokeMsg:"},
    {"BaseMsgContentLogicController",   "onRevokeMsg:"},
    {"RevokeMsgHandler",                "onRevokeMsg:"},
};

// ===========================================================================
#pragma mark - 自适应扫描（排错用，只记录不修改行为）

/// 遍历进程里所有类，找出名字里带 revoke/recall 的方法，写进日志。
/// 用途：微信升级后如果候选表全部失效，可以用这份日志人工定位新入口。
/// 跑在后台队列，且限制输出条数，不干扰主线程。
static void WXARScanCandidates(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        WXARLog(@"扫描：objc_getClassList 返回 %d", count);
        return;
    }
    if (count > 200000) count = 200000;   // 保护
    Class *classes = (Class *)malloc(sizeof(Class) * (size_t)count);
    if (!classes) return;
    count = objc_getClassList(classes, count);

    int hits = 0;
    for (int i = 0; i < count; i++) {
        Class cls = classes[i];
        const char *cname = class_getName(cls);
        if (!cname) continue;

        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(cls, &mcount);
        if (!methods) continue;
        for (unsigned int j = 0; j < mcount; j++) {
            const char *sname = sel_getName(method_getName(methods[j]));
            if (!sname) continue;
            if (WXARContainsRevokeWord(sname) && hits < 200) {
                const char *types = method_getTypeEncoding(methods[j]);
                WXARLog(@"🔍 候选 %s -%s  [%s]", cname, sname, types ? types : "?");
                hits++;
            }
        }
        free(methods);
    }
    free(classes);
    WXARLog(@"扫描结束：%d 个候选方法 / 进程内 %d 个类", hits, count);
}

// ===========================================================================
#pragma mark - 装配

static void WXARInstallHooks(void) {
    int total = (int)(sizeof(kCandidates) / sizeof(kCandidates[0]));
    int ok = 0;
    for (int i = 0; i < total; i++) {
        if (WXARSwizzle([NSString stringWithUTF8String:kCandidates[i].cls],
                        [NSString stringWithUTF8String:kCandidates[i].sel])) {
            ok++;
        }
    }
    // 每轮都完整跑一遍：WXARSwizzle 自带去重，重复调用不会重复替换，
    // 这样即使某个类比预期晚注册，后面的轮次仍然能补上。
    WXARLog(@"本轮命中 %d/%d 个入口", ok, total);
}

static void WXAREntry(void) {
    @autoreleasepool {
        WXARLogInit();

        NSString *bid = [NSBundle mainBundle].bundleIdentifier;
        if (!bid || ![bid isEqualToString:@WXAR_TARGET_BID]) {
            NSLog(@"[anti-revoke] 非微信进程 (%@)，不启用", bid);
            return;
        }

        WXARLog(@"======== 微信防撤回 v%s 已加载 ========", WXAR_VERSION);
        WXARLog(@"设备 %@ / iOS %@",
                [[UIDevice currentDevice] model],
                [[UIDevice currentDevice] systemVersion]);

        size_t rounds = sizeof(kRetryDelays) / sizeof(kRetryDelays[0]);
        for (size_t i = 0; i < rounds; i++) {
            double delay = kRetryDelays[i];
            dispatch_after(
                dispatch_time(DISPATCH_TIME_NOW,
                              (int64_t)(delay * NSEC_PER_SEC)),
                dispatch_get_main_queue(), ^{
                    @autoreleasepool {
                        WXARInstallHooks();
                    }
                });
        }

        // 全部重试结束后，在后台队列跑一次全量扫描，把候选写进日志
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                @autoreleasepool {
                    WXARScanCandidates();
                }
            });
    }
}

__attribute__((constructor))
static void WXARConstructor(void) {
    // constructor 跑在 dyld 初始化阶段，此时 Foundation 还没完全就绪。
    // 把实际工作丢到主队列，等 main() 启动后再执行，最安全。
    dispatch_async(dispatch_get_main_queue(), ^{
        WXAREntry();
    });
}
