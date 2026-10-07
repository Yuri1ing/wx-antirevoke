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

// 诊断开关。
//   1 = 启动弹诊断窗、撤回时弹观察窗、并安装观察模式（排错用）
//   0 = 正式版：不弹任何窗、不装观察模式，只把信息静默写进日志
// 已经验证过 4 个入口全部命中，所以正式版关掉这些干扰。
#define WXAR_DIAGNOSTIC  0

// 「撤回提示」这个功能单独的排错开关。它独立于上面的总开关，
// 因为提示功能最后才做通，排错信息最密集。正式版设为 0。
#define WXAR_TIP_DIAGNOSTIC  0

// 延迟重试的轮次（秒）。微信的类大多在启动阶段就注册好了，
// 留几轮是为了兜底那些懒加载的控制器。
static const double kRetryDelays[] = {0.0, 1.0, 3.0, 6.0, 10.0};

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

static WXARHookRecord gHooks[512];
static int            gHookCount = 0;

// ===========================================================================
#pragma mark - 诊断上报（弹窗版）
//
// 非越狱设备上，沙盒里的日志文件很难取出来看。所以诊断版直接把结果弹到屏幕上：
//   1. 启动若干秒后弹一次，列出「哪些入口 hook 成功 / 哪些没命中 / 为什么」
//   2. 每次真的拦到撤回时再弹一次，证明方法确实被调用了
// 这样一眼就能区分「dylib 没加载」和「加载了但入口不对」。

static NSMutableArray<NSString *> *gDiagHooked  = nil;   // hook 成功
static NSMutableArray<NSString *> *gDiagMissed  = nil;   // 未命中
static NSMutableArray<NSString *> *gDiagRefused = nil;   // 被规则拒绝
static int gDiagHitPopupCount = 0;

static void WXARDiagInit(void) {
    if (gDiagHooked) return;
    gDiagHooked  = [NSMutableArray array];
    gDiagMissed  = [NSMutableArray array];
    gDiagRefused = [NSMutableArray array];
}

static UIViewController *WXARTopViewController(void) {
    UIWindow *keyWindow = nil;
    NSArray<UIWindow *> *windows = [UIApplication sharedApplication].windows;
    for (UIWindow *w in windows) {
        if (w.isKeyWindow) { keyWindow = w; break; }
    }
    if (!keyWindow) keyWindow = windows.firstObject;
    UIViewController *vc = keyWindow.rootViewController;
    if (!vc) return nil;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

/// 弹一个提示。可能被微信的 UI 挡住或者当时还没有窗口，所以失败就静默放弃。
///
/// 正式版（WXAR_DIAGNOSTIC = 0）不弹窗，只把内容写进日志 —— 所有诊断信息都
/// 汇总在这里，所以改这一个地方就能让全部弹窗消失。
static void WXARPopup(NSString *title, NSString *message) {
#if WXAR_DIAGNOSTIC
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIViewController *top = WXARTopViewController();
            if (!top) return;
            UIAlertController *ac =
                [UIAlertController alertControllerWithTitle:title
                                                    message:message
                                             preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了"
                                                   style:UIAlertActionStyleDefault
                                                 handler:nil]];
            [top presentViewController:ac animated:YES completion:nil];
        } @catch (NSException *e) {
            // 弹不出来绝不能影响微信本身
        }
    });
#else
    WXARLog(@"[诊断] %@ —— %@", title, message);
#endif
}

/// 反复尝试弹窗，直到拿到可用的 view controller（最多 12 次，每次隔 1 秒）
static void WXARPopupWhenReady(NSString *title, NSString *message, int attemptsLeft) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            if (WXARTopViewController() || attemptsLeft <= 0) {
                WXARPopup(title, message);
            } else {
                WXARPopupWhenReady(title, message, attemptsLeft - 1);
            }
        }
    });
}

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

// ===========================================================================
#pragma mark - 撤回提示（往聊天框里插一条本地提示消息）
//
// 因为我们拦住了原实现，微信自己那条「XXX撤回了一条消息」也不会出现。
// 这里用微信现成的 API 自己补一条：
//     CMessageWrap  -initWithMsgType:       （0x2710 = 10000，系统提示类型）
//     CMessageMgr   -AddLocalMsg:MsgWrap:fixTime:NewMsgArriveNotify:
// 两个都在 8.0.75 的符号表里实测存在。
//
// 全程 @try 保护 + respondsToSelector 校验：任何一环拿不到就安静放弃，
// 退化成「无提示的防撤回」，绝不让微信崩。
//
// 【关于怎么拿到 CMessageMgr 实例】
// 实测（用户真机反馈）8.0.75 上：
//   - MMServiceCenter 没有任何类方法        → 无法 getService:
//   - CMessageMgr 的类方法只有 9 个工具方法 → 没有单例入口
//   - MessageRevokeMgr 实例的 ivar 里也没有 CMessageMgr
// 所以「主动获取」这条路是死的。改成**反向捕获**：hook CMessageMgr 自己的方法，
// 等微信正常调用它时，把 self 记下来。

// 下面这两个工具函数定义在后面的「观察模式」一节里，
// 但捕获桩要先用，所以这里先做前置声明。
static IMP  WXARObserveOriginal(SEL sel);
static BOOL WXARIsVoidOneObjectArg(const char *types);

static id gCachedMessageMgr = nil;

static void WXARCacheMessageMgr(id mgr) {
    if (!mgr || gCachedMessageMgr) return;
    gCachedMessageMgr = mgr;
    WXARLog(@"✅ 已捕获 CMessageMgr 实例：%s", object_getClassName(mgr));
}

/// 转发桩（1 个对象参数、void 返回）：先记下 self，再照常执行原实现
static void wxar_cachemgr_void1(id self, SEL _cmd, id a1) {
    WXARCacheMessageMgr(self);
    IMP orig = WXARObserveOriginal(_cmd);
    if (orig) {
        ((void (*)(id, SEL, id))orig)(self, _cmd, a1);
    }
}

/// 转发桩（无参数、返回对象）：用于 -init 这类，创建瞬间就捕获
static id wxar_cachemgr_obj0(id self, SEL _cmd) {
    IMP orig = WXARObserveOriginal(_cmd);
    id ret = orig ? ((id (*)(id, SEL))orig)(self, _cmd) : nil;
    WXARCacheMessageMgr(ret ? ret : self);
    return ret;
}

/// 装一个捕获钩子。takesArg=YES 对应「1 个对象参数 + void 返回」，
/// NO 对应「无参数 + 返回对象」。
static BOOL WXARInstallCatcher(Class cls, const char *selName, BOOL takesArg) {
    if (!cls) return NO;
    if (gHookCount >= (int)(sizeof(gHooks) / sizeof(gHooks[0]))) return NO;

    SEL sel = NSSelectorFromString([NSString stringWithUTF8String:selName]);
    for (int i = 0; i < gHookCount; i++) {
        if (gHooks[i].sel == sel) return NO;      // 已处理过
    }
    Method m = WXAROwnMethod(cls, sel);
    if (!m) return NO;

    const char *types = method_getTypeEncoding(m);
    IMP newImp = NULL;
    if (takesArg) {
        if (!WXARIsVoidOneObjectArg(types)) return NO;
        newImp = (IMP)wxar_cachemgr_void1;
    } else {
        if (!types || strcmp(types, "@16@0:8") != 0) return NO;
        newImp = (IMP)wxar_cachemgr_obj0;
    }

    IMP original = method_setImplementation(m, newImp);
    if (!original) return NO;

    WXARHookRecord *rec = &gHooks[gHookCount++];
    rec->cls = cls;
    rec->sel = sel;
    rec->original = original;
    WXARLog(@"装好捕获钩子：CMessageMgr -%s", selName);
    return YES;
}

/// 尽量在 CMessageMgr 被创建/使用之前把这些钩子装上
static int WXARInstallMgrCatcher(void) {
    Class cls = objc_getClass("CMessageMgr");
    if (!cls) return 0;
    int n = 0;

    // 「1 个对象参数 + void」的高频方法，微信跑起来就会调到
    static const char *kCatchSels[] = {
        "InitMsgMgr:",
        "AsyncOnUnReadChange:",
        "reloadRevokeMsgNode:",
        "AddMsgPattern:",
        "checkForSecSystemMsg:",
        "onSecMsg:",
        "UpdateVideoStatus:",
    };
    for (size_t i = 0; i < sizeof(kCatchSels) / sizeof(kCatchSels[0]); i++) {
        if (WXARInstallCatcher(cls, kCatchSels[i], YES)) n++;
    }
    if (WXARInstallCatcher(cls, "init", NO)) n++;

    WXARLog(@"CMessageMgr 捕获钩子装了 %d 个", n);
    return n;
}

/// 无视诊断开关，强制弹窗。只给「撤回提示」这一个功能排错时用。
static void WXARPopupForce(NSString *title, NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIViewController *top = WXARTopViewController();
            if (!top) return;
            UIAlertController *ac =
                [UIAlertController alertControllerWithTitle:title
                                                    message:message
                                             preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了"
                                                   style:UIAlertActionStyleDefault
                                                 handler:nil]];
            [top presentViewController:ac animated:YES completion:nil];
        } @catch (NSException *e) {
            // 弹不出来也不能影响微信
        }
    });
}

/// 剥掉 <![CDATA[ ... ]]> 包装。
/// 微信的 <replacemsg> 内容本身就带 CDATA 壳，
/// 直接显示会变成 <![CDATA["某某" 撤回了一条消息]]>，很难看。
static NSString *WXARStripCDATA(NSString *s) {
    if (s.length == 0) return s;
    NSString *t = [s stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([t hasPrefix:@"<![CDATA["] && [t hasSuffix:@"]]>"] && t.length > 12) {
        return [t substringWithRange:NSMakeRange(8, t.length - 8 - 3)];
    }
    return t;
}

/// 取 <tag>...</tag> 之间的内容
static NSString *WXARTagValue(NSString *xml, NSString *tag) {
    if (!xml || !tag) return nil;
    NSString *open  = [NSString stringWithFormat:@"<%@>", tag];
    NSString *close = [NSString stringWithFormat:@"</%@>", tag];
    NSRange r1 = [xml rangeOfString:open];
    if (r1.location == NSNotFound) return nil;
    NSUInteger start = r1.location + r1.length;
    if (start > xml.length) return nil;
    NSRange r2 = [xml rangeOfString:close options:0
                              range:NSMakeRange(start, xml.length - start)];
    if (r2.location == NSNotFound) return nil;
    return [xml substringWithRange:NSMakeRange(start, r2.location - start)];
}

/// 撤回提示专用的排错上报：第一次失败时弹窗，把原因和探测到的信息一起给出
static NSString *gTipDiag = nil;
static BOOL gTipDiagShown = NO;

static void WXARTipFail(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    WXARLog(@"撤回提示失败：%@", msg);
#if WXAR_TIP_DIAGNOSTIC
    if (gTipDiagShown) return;
    gTipDiagShown = YES;

    NSMutableString *full = [NSMutableString stringWithString:msg];
    if (gTipDiag.length) [full appendFormat:@"\n\n—— 探测信息 ——\n%@", gTipDiag];
    WXARPopupForce(@"⚠️ 撤回提示没插进去", full);
#endif
}

/// 把一个类的所有「类方法」名字收集进诊断串（限 40 条，避免弹窗过长）
static void WXARCollectClassMethods(Class cls, NSString *label, NSMutableString *out) {
    if (!cls) return;
    Class meta = object_getClass(cls);
    unsigned int count = 0;
    Method *methods = class_copyMethodList(meta, &count);
    if (!methods) return;
    [out appendFormat:@"%@ 类方法 (%u)：\n", label, count];
    for (unsigned int i = 0; i < count && i < 40; i++) {
        const char *types = method_getTypeEncoding(methods[i]);
        [out appendFormat:@"  +%s [%s]\n",
                          sel_getName(method_getName(methods[i])),
                          types ? types : "?"];
    }
    free(methods);
}

/// 自动找单例：遍历 cls 的类方法，只调用「无参数且返回对象」(类型编码 @16@0:8) 的，
/// 看哪一个返回的对象能响应 -getService:。
/// 这样就不用去猜 defaultCenter / sharedInstance 这些名字了。
static id WXARAutoFindSingleton(Class cls, NSMutableString *diag) {
    if (!cls) return nil;
    Class meta = object_getClass(cls);
    unsigned int count = 0;
    Method *methods = class_copyMethodList(meta, &count);
    if (!methods) return nil;

    SEL getSel = NSSelectorFromString(@"getService:");
    id found = nil;
    for (unsigned int i = 0; i < count; i++) {
        SEL sel = method_getName(methods[i]);
        const char *types = method_getTypeEncoding(methods[i]);
        if (!types || types[0] != '@') continue;
        if (strcmp(types, "@16@0:8") != 0) continue;   // 必须无参数
        @try {
            id obj = ((id (*)(id, SEL))objc_msgSend)(cls, sel);
            if (!obj) continue;
            [diag appendFormat:@"  调用 +%s 得到 %s\n",
                               sel_getName(sel), object_getClassName(obj)];
            if (!found && [obj respondsToSelector:getSel]) {
                found = obj;
                [diag appendFormat:@"    ↑ 它能响应 getService:，采用它\n"];
            }
        } @catch (NSException *e) {
            [diag appendFormat:@"  调用 +%s 抛异常\n", sel_getName(sel)];
        }
    }
    free(methods);
    return found;
}

/// 从某个实例的 ivar 里找 CMessageMgr（有些 Manager 直接持有消息管理器）
static id WXARFindMgrInIvars(id obj, NSMutableString *diag) {
    if (!obj) return nil;
    Class cls = object_getClass(obj);
    Class mgrCls = objc_getClass("CMessageMgr");
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList(cls, &count);
    if (!ivars) return nil;
    id found = nil;
    for (unsigned int i = 0; i < count; i++) {
        const char *iname = ivar_getName(ivars[i]);
        const char *itype = ivar_getTypeEncoding(ivars[i]);
        @try {
            id val = object_getIvar(obj, ivars[i]);
            if (!val) continue;
            [diag appendFormat:@"  ivar %s [%s] → %s\n", iname ? iname : "?",
                               itype ? itype : "?", object_getClassName(val)];
            if (!found && mgrCls && [val isKindOfClass:mgrCls]) {
                found = val;
                [diag appendFormat:@"    ↑ 命中 CMessageMgr\n"];
            }
        } @catch (NSException *e) {
            // 忽略取不到的 ivar
        }
    }
    free(ivars);
    return found;
}

/// 拿 CMessageMgr 单例。
/// hint 是调用方的实例（MessageRevokeMgr 之类），用于最后一招：翻它的 ivar。
static id WXARMessageMgrFrom(id hint) {
    // 反向捕获到的实例优先（这是正常路径）
    if (gCachedMessageMgr) return gCachedMessageMgr;

    static id cached = nil;
    static BOOL tried = NO;
    if (tried) return cached;
    tried = YES;

    NSMutableString *diag = [NSMutableString string];
    Class mgrCls = objc_getClass("CMessageMgr");
    Class centerCls = objc_getClass("MMServiceCenter");
    [diag appendFormat:@"CMessageMgr 类：%@   MMServiceCenter 类：%@\n\n",
                       mgrCls ? @"有" : @"无", centerCls ? @"有" : @"无"];

    @try {
        // 途径 1：常见单例名硬试
        NSArray<NSString *> *names = @[@"defaultCenter", @"sharedInstance",
                                       @"defaultInstance", @"sharedCenter",
                                       @"getInstance", @"instance", @"shared"];
        id center = nil;
        for (NSString *n in names) {
            SEL s = NSSelectorFromString(n);
            if (centerCls && [centerCls respondsToSelector:s]) {
                center = ((id (*)(id, SEL))objc_msgSend)(centerCls, s);
                [diag appendFormat:@"MMServiceCenter +%@ → %@\n", n,
                                   center ? @"拿到" : @"nil"];
                if (center) break;
            }
        }
        SEL getSel = NSSelectorFromString(@"getService:");
        if (center && [center respondsToSelector:getSel] && mgrCls) {
            cached = ((id (*)(id, SEL, Class))objc_msgSend)(center, getSel, mgrCls);
            [diag appendFormat:@"getService:CMessageMgr → %@\n", cached ? @"拿到" : @"nil"];
        }

        // 途径 2：自动扫描 MMServiceCenter 的类方法
        if (!cached) {
            [diag appendString:@"\n--- 自动扫描 MMServiceCenter ---\n"];
            id auto1 = WXARAutoFindSingleton(centerCls, diag);
            if (auto1 && [auto1 respondsToSelector:getSel] && mgrCls) {
                cached = ((id (*)(id, SEL, Class))objc_msgSend)(auto1, getSel, mgrCls);
                [diag appendFormat:@"自动途径 getService:CMessageMgr → %@\n",
                                   cached ? @"拿到" : @"nil"];
            }
        }

        // 途径 3：自动扫描 CMessageMgr 自己的类方法
        if (!cached) {
            [diag appendString:@"\n--- 自动扫描 CMessageMgr ---\n"];
            cached = WXARAutoFindSingleton(mgrCls, diag);
        }

        // 途径 4：翻调用方实例的 ivar（很多 Manager 直接持有消息管理器）
        if (!cached && hint) {
            [diag appendString:@"\n--- 翻调用方 ivar ---\n"];
            cached = WXARFindMgrInIvars(hint, diag);
        }

        // 途径 5：都没找到，列出类方法供人工判断
        if (!cached) {
            [diag appendString:@"\n--- 未找到，列出类方法供人工判断 ---\n"];
            WXARCollectClassMethods(centerCls, @"MMServiceCenter", diag);
            WXARCollectClassMethods(mgrCls, @"CMessageMgr", diag);
        }
    } @catch (NSException *e) {
        [diag appendFormat:@"探测时抛异常：%@\n", e.reason];
    }

    gTipDiag = diag;
    if (cached) WXARLog(@"已拿到 CMessageMgr");
    return cached;
}

/// 同一个会话 2 秒内只插一条，避免多个 hook 点重复触发时刷屏
static BOOL WXARTipAllowed(NSString *session) {
    if (session.length == 0) return NO;
    static NSMutableDictionary<NSString *, NSNumber *> *lastTime = nil;
    if (!lastTime) lastTime = [NSMutableDictionary dictionary];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSNumber *last = lastTime[session];
    if (last && now - last.doubleValue < 2.0) return NO;
    lastTime[session] = @(now);
    if (lastTime.count > 200) [lastTime removeAllObjects];   // 防膨胀
    return YES;
}

/// 尝试往聊天框里插一条「拦截了撤回」的提示
static void WXARTryInsertRevokeTip(id owner, id arg) {
    @try {
        if (!arg) {
            WXARTipFail(@"拦截到的参数是 nil");
            return;
        }

        NSMutableString *info = [NSMutableString string];
        [info appendFormat:@"参数类型：%s\n", object_getClassName(arg)];

        // 1) 从参数里掏 session 和原始内容（参数可能是 CMessageWrap，也可能是 XML 字符串）
        NSString *session = nil;
        NSString *content = nil;
        if ([arg respondsToSelector:NSSelectorFromString(@"m_nsFromUsr")]) {
            session = [arg valueForKey:@"m_nsFromUsr"];
        }
        if ([arg respondsToSelector:NSSelectorFromString(@"m_nsContent")]) {
            content = [arg valueForKey:@"m_nsContent"];
        }
        if (!content && [arg isKindOfClass:[NSString class]]) {
            content = (NSString *)arg;
        }

        [info appendFormat:@"m_nsFromUsr：%@\n", session.length ? session : @"(空)"];
        if (content.length > 150) {
            [info appendFormat:@"m_nsContent：%@…\n",
                               [content substringToIndex:150]];
        } else {
            [info appendFormat:@"m_nsContent：%@\n", content.length ? content : @"(空)"];
        }

        if (session.length == 0 && content) {
            session = WXARTagValue(content, @"session");
        }
        if (session.length == 0) {
            gTipDiag = info;
            WXARTipFail(@"从参数里取不到 session（会话标识）");
            return;
        }
        if (!WXARTipAllowed(session)) return;   // 2 秒内重复，静默跳过

        // 2) 构造一条系统提示消息
        Class wrapCls = objc_getClass("CMessageWrap");
        if (!wrapCls) {
            gTipDiag = info;
            WXARTipFail(@"找不到 CMessageWrap 类");
            return;
        }
        id tip = ((id (*)(id, SEL, long long))objc_msgSend)(
            [wrapCls alloc], NSSelectorFromString(@"initWithMsgType:"), 0x2710LL);
        if (!tip) {
            gTipDiag = info;
            WXARTipFail(@"CMessageWrap initWithMsgType: 创建失败");
            return;
        }

        // 提示文案优先用微信自己生成的 <replacemsg>：
        // 它在私聊里是「对方」，在群聊里会带上具体昵称。
        // 注意：它的内容是**带 CDATA 壳**的（<![CDATA["某某" 撤回了一条消息]]>），
        // 所以要把壳剥掉，否则聊天框里会显示一串尖括号。
        NSString *tipText = WXARTagValue(content, @"replacemsg");
        if ([tipText hasPrefix:@"<![CDATA["] && [tipText hasSuffix:@"]]>"]
            && tipText.length > 12) {
            tipText = [tipText substringWithRange:NSMakeRange(9, tipText.length - 12)];
        }
        if (tipText.length == 0) {
            // 退一步：从 CDATA 里抠出「XXX撤回了一条消息」
            NSString *src = content ? content : @"";
            NSRegularExpression *re = [NSRegularExpression
                regularExpressionWithPattern:@"<!\\[CDATA\\[(.*?撤回.*?)\\]\\]>"
                                     options:NSRegularExpressionCaseInsensitive
                                       error:nil];
            NSTextCheckingResult *m = [re firstMatchInString:src
                                                     options:0
                                                       range:NSMakeRange(0, src.length)];
            if (m && m.numberOfRanges >= 2) {
                tipText = [src substringWithRange:[m rangeAtIndex:1]];
            }
        }
        if (tipText.length == 0) {
            tipText = @"对方撤回了一条消息";
        }
        tipText = [tipText stringByAppendingString:@"（已被防撤回拦截，原消息保留）"];

        [tip setValue:session forKey:@"m_nsFromUsr"];
        [tip setValue:session forKey:@"m_nsToUsr"];
        [tip setValue:tipText forKey:@"m_nsContent"];
        [tip setValue:@(0x4) forKey:@"m_uiStatus"];
        [tip setValue:@((uint32_t)[[NSDate date] timeIntervalSince1970])
                forKey:@"m_uiCreateTime"];

        // 3) 交给消息管理器写进本地会话
        id mgr = WXARMessageMgrFrom(owner);
        if (!mgr) {
            // gTipDiag 已在 WXARMessageMgr 里填好
            WXARTipFail(@"拿不到 CMessageMgr 实例");
            return;
        }
        SEL addSel = NSSelectorFromString(@"AddLocalMsg:MsgWrap:fixTime:NewMsgArriveNotify:");
        if (![mgr respondsToSelector:addSel]) {
            gTipDiag = info;
            WXARTipFail(@"CMessageMgr 不响应 AddLocalMsg:MsgWrap:fixTime:NewMsgArriveNotify:");
            return;
        }

        ((void (*)(id, SEL, id, id, BOOL, BOOL))objc_msgSend)(
            mgr, addSel, session, tip, YES, NO);
        WXARLog(@"✅ 已插入撤回提示：session=%@", session);
#if WXAR_TIP_DIAGNOSTIC
        WXARPopupForce(@"✅ 撤回提示已插入",
                       [NSString stringWithFormat:@"session：%@\n\n如果聊天框里没看到，"
                        @"说明消息插进去了但没显示，那是消息类型/状态字段的问题。",
                        session]);
#endif
    } @catch (NSException *e) {
        WXARTipFail(@"插入过程抛异常：%@", e.reason);
    }
}

static void WXARNoteHit(id self, SEL _cmd, id arg) {
    const char *argCls = "nil";
    if (arg) {
        // 用 C 函数取类名，比发消息更轻、更不容易出意外
        argCls = object_getClassName(arg);
    }
    NSString *desc = [NSString stringWithFormat:@"%@ -%@  参数类型: %s",
                      NSStringFromClass([self class]),
                      NSStringFromSelector(_cmd), argCls];
    WXARLog(@"🛡 已拦截撤回  %@", desc);

    // 往聊天框里补一条提示（失败也不会影响防撤回本身）
    WXARTryInsertRevokeTip(self, arg);

    // 诊断版：真的拦到撤回时弹窗报喜，最多弹 5 次免得刷屏
    if (gDiagHitPopupCount < 5) {
        gDiagHitPopupCount++;
        WXARPopup(@"✅ 防撤回已生效",
                  [NSString stringWithFormat:@"拦截到撤回入口：\n\n%@\n\n(第 %d 次)",
                   desc, gDiagHitPopupCount]);
    }
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
    WXARDiagInit();

    // 注意：安装会分多轮重试，所以诊断记录必须去重，否则报告里全是重复项
    Class cls = objc_getClass(clsName.UTF8String);
    if (!cls) {
        NSString *line = [NSString stringWithFormat:@"%@ -%@ (类未注册)",
                          clsName, selName];
        if (![gDiagMissed containsObject:line]) [gDiagMissed addObject:line];
        return NO;
    }

    SEL sel = NSSelectorFromString(selName);
    Method m = WXAROwnMethod(cls, sel);
    if (!m) {
        NSString *line = [NSString stringWithFormat:@"%@ -%@ (该类未定义)",
                          clsName, selName];
        if (![gDiagMissed containsObject:line]) [gDiagMissed addObject:line];
        return NO;
    }

    // 双保险：方法名里必须真的含 revoke / recall
    const char *selCStr = sel_getName(sel);
    if (!WXARContainsRevokeWord(selCStr)) {
        NSString *line = [NSString stringWithFormat:@"%@ -%@ (名字不含 revoke)",
                          clsName, selName];
        if (![gDiagRefused containsObject:line]) [gDiagRefused addObject:line];
        WXARLog(@"拒绝 hook %@ -%@：方法名不含 revoke/recall", clsName, selName);
        return NO;
    }

    // 已经 hook 过就不重复（也不重复记诊断）
    for (int i = 0; i < gHookCount; i++) {
        if (gHooks[i].cls == cls && gHooks[i].sel == sel) return YES;
    }
    if (gHookCount >= (int)(sizeof(gHooks) / sizeof(gHooks[0]))) {
        NSString *line = [NSString stringWithFormat:@"%@ -%@ (替换表已满)",
                          clsName, selName];
        if (![gDiagMissed containsObject:line]) [gDiagMissed addObject:line];
        return NO;
    }

    const char *types = method_getTypeEncoding(m);
    WXARStub stub = WXARStubForEncoding(types);
    IMP newImp = WXARImpForStub(stub);
    if (!newImp) {
        NSString *line = [NSString stringWithFormat:@"%@ -%@ (返回类型 %s 不支持)",
                          clsName, selName, types ? types : "?"];
        if (![gDiagRefused containsObject:line]) [gDiagRefused addObject:line];
        WXARLog(@"放弃 %@ -%@：返回类型无法识别 [%s]", clsName, selName,
                types ? types : "?");
        return NO;
    }

    IMP original = method_setImplementation(m, newImp);
    if (!original) {
        NSString *line = [NSString stringWithFormat:@"%@ -%@ (替换失败)",
                          clsName, selName];
        if (![gDiagMissed containsObject:line]) [gDiagMissed addObject:line];
        return NO;
    }

    WXARHookRecord *rec = &gHooks[gHookCount++];
    rec->cls = cls;
    rec->sel = sel;
    rec->original = original;

    [gDiagHooked addObject:[NSString stringWithFormat:@"%@ -%@  [%s]",
                            clsName, selName, types ? types : "?"]];
    WXARLog(@"✅ 已拦截 %@ -%@   [%s]", clsName, selName, types ? types : "?");
    return YES;
}

// ===========================================================================
#pragma mark - 观察模式（只记录，绝不改变行为）
//
// 目的：万一候选表猜错了入口，还能知道「撤回时到底走了哪些方法」。
// 安全性：只包装「void 返回 + 恰好一个对象参数」的方法，桩函数原样调用原实现，
//        参数传递完全一致，所以行为与不包装时相同。
//        同一个 SEL 只包装一次，避免按 SEL 取原实现时取错。

typedef void (*WXARObsFn)(id, SEL, id);

static NSMutableArray<NSString *> *gObserved = nil;
static BOOL gObservePopupScheduled = NO;

/// 严格匹配形如 v24@0:8@16 的签名：void 返回 + 恰好一个对象参数。
/// 只有这种签名才能用一参数桩安全地转发，多一个参数就会串寄存器。
static BOOL WXARIsVoidOneObjectArg(const char *types) {
    if (!types) return NO;
    const char *p = types;
    if (*p != 'v') return NO;
    p++;
    while (*p >= '0' && *p <= '9') p++;
    if (*p != '@') return NO;
    p++;
    while (*p >= '0' && *p <= '9') p++;
    if (*p != ':') return NO;
    p++;
    while (*p >= '0' && *p <= '9') p++;
    if (*p != '@') return NO;
    p++;
    while (*p >= '0' && *p <= '9') p++;
    return (*p == '\0');
}

static IMP WXARObserveOriginal(SEL sel) {
    for (int i = 0; i < gHookCount; i++) {
        if (gHooks[i].sel == sel) return gHooks[i].original;
    }
    return NULL;
}

/// 收集观察结果，攒 2 秒一次性弹出，避免被刷屏
static void WXARRecordObservation(NSString *line) {
    if (!gObserved) gObserved = [NSMutableArray array];
    @synchronized (gObserved) {
        if (gObserved.count > 200) return;
        [gObserved addObject:line];
    }
    WXARLog(@"👀 %@", line);

    if (gObservePopupScheduled) return;
    gObservePopupScheduled = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        gObservePopupScheduled = NO;
        NSArray *snapshot = nil;
        @synchronized (gObserved) {
            snapshot = [gObserved copy];
            [gObserved removeAllObjects];
        }
        if (snapshot.count == 0) return;
        NSMutableString *m = [NSMutableString stringWithString:@"撤回时这些方法被调用了：\n\n"];
        NSUInteger n = snapshot.count > 25 ? 25 : snapshot.count;
        for (NSUInteger i = 0; i < n; i++) {
            [m appendFormat:@"%@\n", snapshot[i]];
        }
        WXARPopup(@"👀 观察到撤回动作", m);
    });
}

static void wxar_observe_void1(id self, SEL _cmd, id a1) {
    WXARRecordObservation([NSString stringWithFormat:@"%@ -%@",
        NSStringFromClass([self class]), NSStringFromSelector(_cmd)]);
    IMP orig = WXARObserveOriginal(_cmd);
    if (orig) {
        ((WXARObsFn)orig)(self, _cmd, a1);   // 照常执行，行为不变
    }
}

static BOOL WXARSwizzleObserve(Class cls, SEL sel) {
    if (gHookCount >= (int)(sizeof(gHooks) / sizeof(gHooks[0]))) return NO;
    for (int i = 0; i < gHookCount; i++) {
        if (gHooks[i].sel == sel) return NO;   // 同 SEL 已处理，不重复包装
    }
    Method m = WXAROwnMethod(cls, sel);
    if (!m) return NO;
    IMP original = method_setImplementation(m, (IMP)wxar_observe_void1);
    if (!original) return NO;

    WXARHookRecord *rec = &gHooks[gHookCount++];
    rec->cls = cls;
    rec->sel = sel;
    rec->original = original;
    return YES;
}

static int WXARInstallObservers(void) {
#if !WXAR_DIAGNOSTIC
    // 正式版不装观察模式。它会额外包装几百个方法（虽然只记录、照常调用原实现，
    // 行为不变），但对日常使用是多余的负担，装它只是为了当初定位撤回入口。
    return 0;
#else
    int installed = 0;
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return 0;
    if (count > 200000) count = 200000;
    Class *classes = (Class *)malloc(sizeof(Class) * (size_t)count);
    if (!classes) return 0;
    count = objc_getClassList(classes, count);

    for (int i = 0; i < count; i++) {
        Class cls = classes[i];
        const char *cname = class_getName(cls);
        if (!cname || !WXARContainsRevokeWord(cname)) continue;

        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(cls, &mcount);
        if (!methods) continue;
        for (unsigned int j = 0; j < mcount; j++) {
            SEL sel = method_getName(methods[j]);
            const char *sname = sel_getName(sel);
            if (!sname || !WXARContainsRevokeWord(sname)) continue;
            if (!WXARIsVoidOneObjectArg(method_getTypeEncoding(methods[j]))) continue;
            if (installed >= 400) continue;          // 上限保护，别把表塞满
            if (WXARSwizzleObserve(cls, sel)) installed++;
        }
        free(methods);
    }
    free(classes);
    WXARLog(@"观察模式：包装了 %d 个方法", installed);
    return installed;
#endif
}

// ===========================================================================
#pragma mark - 转发 hook 基础设施

/// 按 (类, 方法) 精确取回原实现。
///
/// 为什么不能只按 SEL：像 `layoutSubviews` 这种每个 UIView 都有的方法，
/// 只按 SEL 查找会命中别的类记录的那条，拿到错误的 IMP，一调用就崩。
static IMP WXAROriginalForClass(Class cls, SEL sel) {
    for (int i = 0; i < gHookCount; i++) {
        if (gHooks[i].cls == cls && gHooks[i].sel == sel) return gHooks[i].original;
    }
    // 退一步：本类没记录时按 SEL 找（适用于只 hook 了父类的情形）
    for (int i = 0; i < gHookCount; i++) {
        if (gHooks[i].sel == sel) return gHooks[i].original;
    }
    return NULL;
}

/// 安装一个「转发桩」：新实现自己负责调用原实现，行为不改变，只是多做了点事。
/// 与 WXARSwizzle 的区别是后者会拦断原实现（那是防撤回用的）。
static BOOL WXARInstallForwarder(const char *clsName, const char *selName, IMP newImp) {
    Class cls = objc_getClass(clsName);
    if (!cls) return NO;

    SEL sel = NSSelectorFromString([NSString stringWithUTF8String:selName]);
    for (int i = 0; i < gHookCount; i++) {
        if (gHooks[i].cls == cls && gHooks[i].sel == sel) return YES;   // 已装过
    }
    Method m = WXAROwnMethod(cls, sel);
    if (!m) return NO;
    if (gHookCount >= (int)(sizeof(gHooks) / sizeof(gHooks[0]))) return NO;

    IMP original = method_setImplementation(m, newImp);
    if (!original) return NO;

    WXARHookRecord *rec = &gHooks[gHookCount++];
    rec->cls = cls;
    rec->sel = sel;
    rec->original = original;
    WXARLog(@"装上转发钩子：%@ -%@", [NSString stringWithUTF8String:clsName],
            [NSString stringWithUTF8String:selName]);
    return YES;
}

// ===========================================================================
#pragma mark - 液态玻璃（底部栏）
//
// 目标：把微信主界面底部那条栏（微信/通讯录/发现/我）换成 iOS 26 的液态玻璃。
//
// 挂载点来自对 8.0.79 符号表的分析：`WCTabBarView`（55 个方法）就是那条栏，
// 它自带一个 `backgroundContentView`（背景视图）和一个 `separatorView`（分隔线）。
// 做法是把一个装了 UIGlassEffect 的 UIVisualEffectView 垫到最底层，
// 再把微信自己的背景调成透明，让玻璃透出来。
//
// 只在 iOS 26+ 生效：UIGlassEffect 这个类是 iOS 26 才有的，
// 低版本系统里 NSClassFromString 返回 nil，整段逻辑自动跳过。

#define WXAR_GLASS_TAG   0x7A115300

// 液态玻璃专用诊断弹窗。只报这一个功能的状态，和别的诊断开关相互独立。
// 定位完把这里改成 0 即可。
#define WXAR_GLASS_DIAGNOSTIC  0

static BOOL gGlassReported = NO;
static NSMutableSet<NSString *> *gGlassTouched = nil;   // 哪些类的钩子被触发过

/// 打印一个对象的继承链，用来确认它到底是什么类
static NSString *WXARClassChain(id obj) {
    NSMutableString *s = [NSMutableString string];
    Class c = object_getClass(obj);
    int depth = 0;
    while (c && depth < 8) {
        [s appendFormat:@"%@ < ", NSStringFromClass(c)];
        c = class_getSuperclass(c);
        depth++;
    }
    [s appendString:@"(root)"];
    return s;
}

/// 把视图层级描述成文字，用来判断是谁挡住了玻璃
static NSString *WXARDescribeSubviews(UIView *v) {
    NSMutableString *s = [NSMutableString string];
    NSArray<UIView *> *subs = v.subviews;
    [s appendFormat:@"子视图 %lu 个：\n", (unsigned long)subs.count];
    NSUInteger n = subs.count > 15 ? 15 : subs.count;
    for (NSUInteger i = 0; i < n; i++) {
        UIView *sub = subs[i];
        UIColor *bg = sub.backgroundColor;
        CGFloat alpha = bg ? CGColorGetAlpha(bg.CGColor) : 0.0;
        NSString *bgDesc = (alpha < 0.01)
            ? @"透明"
            : [NSString stringWithFormat:@"不透明α%.2f", alpha];
        [s appendFormat:@"%lu.%@ %@ %.0f×%.0f\n",
            (unsigned long)i, NSStringFromClass([sub class]), bgDesc,
            sub.frame.size.width, sub.frame.size.height];
        // UIVisualEffectView 额外报一下它挂的 effect 是什么。
        // 微信自己的底栏背景就是这种视图，它的 effect 能直接告诉我们
        // iOS 26 上「正确用法」长什么样 —— 比我猜要可靠得多。
        if ([sub isKindOfClass:[UIVisualEffectView class]]) {
            id eff = [(UIVisualEffectView *)sub effect];
            [s appendFormat:@"     └ effect: %@  hidden: %@  alpha: %.2f\n",
                eff ? NSStringFromClass([eff class]) : @"(nil)",
                sub.hidden ? @"是" : @"否", sub.alpha];
        }
    }
    return s;
}

/// 列出运行时所有类名里含 "Glass" 的类。
/// 液态玻璃是 iOS 26 新东西，公开资料里查不到完整 API 清单，
/// 与其猜，不如直接问系统：到底有哪些相关的类。
static NSString *WXARListGlassClasses(void) {
    NSMutableString *result = [NSMutableString string];
    @try {
        int count = objc_getClassList(NULL, 0);
        if (count <= 0) return @"(拿不到类列表)";
        Class *classes = (Class *)malloc(sizeof(Class) * (size_t)count);
        if (!classes) return @"(内存分配失败)";
        count = objc_getClassList(classes, count);
        NSMutableArray<NSString *> *hits = [NSMutableArray array];
        for (int i = 0; i < count; i++) {
            const char *name = class_getName(classes[i]);
            if (name && strstr(name, "Glass")) {
                [hits addObject:[NSString stringWithUTF8String:name]];
            }
        }
        free(classes);
        [hits sortUsingSelector:@selector(compare:)];
        if (hits.count == 0) {
            [result appendString:@"  (一个都没有)"];
        } else {
            for (NSString *n in hits) {
                [result appendFormat:@"  %@\n", n];
            }
        }
    } @catch (NSException *e) {
        [result appendFormat:@"  (异常：%@)", e.reason];
    }
    return result;
}

/// App 是否声明了 iOS 26 的「旧设计兼容模式」。
///
/// 微信 8.0.79 的 Info.plist 里 UIDesignRequiresCompatibility = true
/// （已从 IPA 里实读确认），而它又是用 iphoneos26.1 SDK 编译的。
/// 这个组合会让系统在整个 App 内禁用液态玻璃 —— 所有 UIGlassEffect
/// 都渲染成完全透明。这不是写错了 API，是宿主 App 主动关掉了这条路。
static BOOL WXARAppUsesLegacyDesign(void) {
    @try {
        id v = [[NSBundle mainBundle]
            objectForInfoDictionaryKey:@"UIDesignRequiresCompatibility"];
        if (v && [v respondsToSelector:@selector(boolValue)]) {
            return [v boolValue];
        }
    } @catch (NSException *e) { }
    return NO;
}

static void WXARGlassReport(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    WXARLog(@"[玻璃] %@", msg);
#if WXAR_GLASS_DIAGNOSTIC
    if (gGlassReported) return;
    gGlassReported = YES;
    WXARPopupForce(@"🪟 液态玻璃诊断", msg);
#endif
}

/// 延迟 3 秒再汇总弹窗，这样能顺带收集「哪些类的钩子被触发过」
static void WXARScheduleGlassReport(NSString *detail) {
#if WXAR_GLASS_DIAGNOSTIC
    static BOOL scheduled = NO;
    if (scheduled) return;
    scheduled = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSMutableString *m = [NSMutableString stringWithString:detail];
        [m appendFormat:@"\n触发过的类：%@",
            gGlassTouched.count
                ? [[gGlassTouched allObjects] componentsJoinedByString:@", "]
                : @"(无)"];
        WXARGlassReport(@"%@", m);
    });
#else
    (void)detail;
#endif
}

/// 把玻璃垫到某个栏的底层；幂等，重复调用只更新尺寸。
static void WXARApplyGlassToView(UIView *bar) {
    if (!bar) return;

    // 先看是不是已经装过了
    UIVisualEffectView *glass = nil;
    for (UIView *sub in bar.subviews) {
        if (sub.tag == WXAR_GLASS_TAG) {
            glass = (UIVisualEffectView *)sub;
            break;
        }
    }

    if (!glass) {
        Class glassCls = NSClassFromString(@"UIGlassEffect");
        if (!glassCls) {
            WXARGlassReport(@"❌ 系统里没有 UIGlassEffect 这个类\n\n"
                            @"说明系统低于 iOS 26，液态玻璃用不了。\n"
                            @"当前系统：%@",
                            [[UIDevice currentDevice] systemVersion]);
            return;
        }

        id effect = nil;
        BOOL legacyDesign = WXARAppUsesLegacyDesign();
        if (legacyDesign) {
            // 兼容模式下 UIGlassEffect 渲染出来是全透明的，等于没用。
            // 退回仍然可用的老材质：systemUltraThinMaterial 在所有系统版本上
            // 都能出半透明模糊，观感最接近液态玻璃 —— 这是兼容模式下
            // 能拿到的最好结果（枚举值 6 = SystemUltraThinMaterial）。
            @try {
                Class blurCls = NSClassFromString(@"UIBlurEffect");
                SEL mk = NSSelectorFromString(@"effectWithStyle:");
                if (blurCls && [blurCls respondsToSelector:mk]) {
                    effect = ((id (*)(id, SEL, NSInteger))objc_msgSend)(blurCls, mk, 6);
                }
            } @catch (NSException *e) {
                effect = nil;
            }
            if (!effect) {
                WXARGlassReport(@"❌ 兼容模式下 UIBlurEffect 也没能创建\n\n"
                                @"系统：%@", [[UIDevice currentDevice] systemVersion]);
                return;
            }
            WXARLog(@"[玻璃] 检测到旧设计兼容模式，改用 UIBlurEffect 材质");
        } else {
            @try {
                effect = ((id (*)(id, SEL))objc_msgSend)([glassCls alloc],
                                                         NSSelectorFromString(@"init"));
            } @catch (NSException *e) {
                effect = nil;
            }
            if (!effect) {
                WXARGlassReport(@"❌ UIGlassEffect 创建失败：alloc/init 返回了 nil");
                return;
            }
        }

        // 【诊断结论】上一版给 effect 加的蓝色 tint 在真机上一点没显出来，
        // 说明问题不在于「玻璃很淡」——浓到 55% 的蓝都看不见，只能是这一层
        // 根本没显示出来。所以这次换一个更硬的判据：直接给玻璃的 contentView
        // 铺红色背景。contentView 位于 effect 之上，不经过模糊采样，
        // 只要这个视图真的显示在屏幕上，底栏就必然偏红。

        @try {
            // UIGlassEffect 是 UIVisualEffect 的子类
            UIVisualEffectView *v =
                [[UIVisualEffectView alloc] initWithEffect:(UIVisualEffect *)effect];
            v.tag = WXAR_GLASS_TAG;
            v.userInteractionEnabled = NO;      // 别挡住点击
            v.autoresizingMask = UIViewAutoresizingFlexibleWidth |
                                 UIViewAutoresizingFlexibleHeight;
            [bar insertSubview:v atIndex:0];    // 垫到最底层
            glass = v;
        } @catch (NSException *e) {
            WXARGlassReport(@"❌ 创建 UIVisualEffectView 时抛异常：%@", e.reason);
            return;
        }
    }

    glass.frame = bar.bounds;

    // 【观感修饰】兼容模式下 UIGlassEffect 被系统禁用，退回 UIBlurEffect 兜底。
    // 但 UIBlurEffect 模糊的是「它背后的内容」，而微信底栏背后就是纯黑 ——
    // 模糊纯黑出来还是纯黑，于是真机反馈就成了「图标对齐了，但完全没有玻璃感」。
    //
    // iOS 26 真液态玻璃在背后没有内容可采样时，观感其实主要靠两处人工痕迹撑着：
    //   ① 比背景亮一档的半透明填充
    //   ② 顶部一条极细的高光边
    // 真玻璃模式下这两样由系统绘制，兼容模式下没有，这里手工补上，
    // 让底栏至少是一块「玻璃片」，而不是一块死黑。
    //
    // 只在兼容模式下加：真玻璃模式下系统自己会画，再加一遍就糊了。
    if (WXARAppUsesLegacyDesign()) {
        @try {
            const NSInteger kFillTag = 0x7A115301;
            BOOL already = NO;
            for (UIView *cv in glass.contentView.subviews) {
                if (cv.tag == kFillTag) { already = YES; break; }
            }
            if (!already) {
                // ① 半透明填充：把底栏整体提亮一档，和纯黑列表背景拉开层次
                UIView *fill = [[UIView alloc] initWithFrame:glass.bounds];
                fill.tag = kFillTag;
                fill.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.10];
                fill.userInteractionEnabled = NO;
                fill.autoresizingMask = UIViewAutoresizingFlexibleWidth |
                                        UIViewAutoresizingFlexibleHeight;
                [glass.contentView addSubview:fill];

                // ② 顶部高光：0.5pt 的白色细线，模拟玻璃边缘的反光
                UIView *hl = [[UIView alloc] initWithFrame:
                                CGRectMake(0, 0, glass.bounds.size.width, 0.5)];
                hl.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.35];
                hl.userInteractionEnabled = NO;
                hl.autoresizingMask = UIViewAutoresizingFlexibleWidth;
                [glass.contentView addSubview:hl];
            }
        } @catch (NSException *e) { }
    }

    // 1) 微信自带的背景视图（WCTabBarView 有 backgroundContentView 属性）
    @try {
        id bg = [bar valueForKey:@"backgroundContentView"];
        if ([bg isKindOfClass:[UIView class]]) {
            UIView *bgView = (UIView *)bg;
            if (bgView.backgroundColor &&
                ![bgView.backgroundColor isEqual:[UIColor clearColor]]) {
                bgView.backgroundColor = [UIColor clearColor];
            }
        }
    } @catch (NSException *e) {
        // KVC 取不到就算了，不影响主流程
    }

    // 2) 栏自身背景
    if (bar.backgroundColor && ![bar.backgroundColor isEqual:[UIColor clearColor]]) {
        bar.backgroundColor = [UIColor clearColor];
    }

    // 3) 逐个子视图清理遮挡。
    //
    //    真机实测：MMTabBar 里第 0 层是微信自己的 UIVisualEffectView（α1.00），
    //    正好盖在玻璃上面。而 UIVisualEffectView 的外观来自 `effect` 属性，
    //    光设 backgroundColor 对它没用 —— 必须把 effect 拿掉并隐藏。
    //    其余层是普通背景色，调透明即可。
    for (UIView *sub in bar.subviews) {
        if (sub == glass) continue;
        @try {
            NSString *clsName = NSStringFromClass([sub class]);
            // iOS 26 新设计下，系统的 UITabBar 会额外画一块悬浮胶囊形的底板：
            // UIKit._UITabBarPlatterView，比底栏本身内缩（实测 351×69 vs 393×90）。
            //
            // 微信是自己画图标的，根本不往系统 tabBar 里放 item，所以这个 platter
            // 是个什么都没有的空盘子 —— 它和微信自绘的 MMTabBarItemView 错开显示，
            // 于是就成了「两个底栏 + 图标错位 + 玻璃层没图标」。
            // 直接藏掉，只留我们的玻璃和微信自己的图标。
            if ([clsName containsString:@"Platter"]) {
                sub.hidden = YES;
                continue;
            }
            if ([sub isKindOfClass:[UIVisualEffectView class]]) {
                UIVisualEffectView *ve = (UIVisualEffectView *)sub;
                ve.effect = nil;
                ve.backgroundColor = [UIColor clearColor];
                ve.hidden = YES;              // 让我们的液态玻璃露出来
                continue;
            }
            UIColor *bg = sub.backgroundColor;
            if (bg && CGColorGetAlpha(bg.CGColor) > 0.01) {
                sub.backgroundColor = [UIColor clearColor];
            }
        } @catch (NSException *e) { }
    }

    // 4) 某些布局周期里微信会重排子视图，把玻璃挤到后面去。
    //    每次都重新插回底层，保证它一直在最下面。
    [bar insertSubview:glass atIndex:0];

    // 5) 关键一步：MMTabBar 其实是 UITabBar 的子类（子视图里有 _UIBarBackground
    //    和 UITabBarButton 这些私有类名可以佐证）。UITabBar 的背景由
    //    UITabBarAppearance 统一绘制 —— 在视图层面改 backgroundColor 会被它
    //    在下一个布局周期覆盖回去，必须把外观对象本身设成透明。
    //
    //    上一版这里踩了坑：直接 alloc 一个全新的 UITabBarAppearance 盖上去，
    //    等于把微信自己设过的整套外观参数（item 宽度、文字偏移等）清成默认值。
    //    结果系统那 4 个 UITabBarButton 摆到了错误位置，和微信自绘的
    //    MMTabBarItemView 错开显示 —— 底栏就出现了上下两排文字。
    //
    //    正确做法：取微信现有的 appearance，copy 一份再改背景，只动背景这一个属性。
    @try {
        SEL getStd = NSSelectorFromString(@"standardAppearance");
        SEL setStd = NSSelectorFromString(@"setStandardAppearance:");
        SEL setEdge = NSSelectorFromString(@"setScrollEdgeAppearance:");
        if ([bar respondsToSelector:getStd] && [bar respondsToSelector:setStd]) {
            id ap = ((id (*)(id, SEL))objc_msgSend)(bar, getStd);
            if (!ap) {
                Class apCls = NSClassFromString(@"UITabBarAppearance");
                if (apCls) {
                    ap = ((id (*)(id, SEL))objc_msgSend)([apCls alloc],
                                                         NSSelectorFromString(@"init"));
                }
            }
            if (ap) {
                // 关键：复制而非新建，微信原有的外观参数原样保留
                SEL copySel = NSSelectorFromString(@"copy");
                if ([ap respondsToSelector:copySel]) {
                    id copied = ((id (*)(id, SEL))objc_msgSend)(ap, copySel);
                    if (copied) ap = copied;
                }
                SEL cfgSel = NSSelectorFromString(@"configureWithTransparentBackground");
                if ([ap respondsToSelector:cfgSel]) {
                    ((void (*)(id, SEL))objc_msgSend)(ap, cfgSel);
                }
                ((void (*)(id, SEL, id))objc_msgSend)(bar, setStd, ap);
                if ([bar respondsToSelector:setEdge]) {
                    ((void (*)(id, SEL, id))objc_msgSend)(bar, setEdge, ap);
                }
                WXARLog(@"[玻璃] 已在微信原有 appearance 基础上设为透明背景");
            }
        }
    } @catch (NSException *e) {
        WXARLog(@"[玻璃] 设置 appearance 失败：%@", e.reason);
    }

    // 6) 不再手动隐藏 _UIBarBackground。
    //    上一步已经把 appearance 背景设透明，系统自己就会让这个视图变透明；
    //    手动 hidden 属于多余的干预，可能干扰系统内部的布局逻辑。
    //
    //    另外它也只是「背景」层，并不能解释底栏为什么还是不透 —— 要继续查的话
    //    得看 MMTabBar 的父视图链上谁还是不透明的。

    // 装好了才报告，并把子视图层级一起带上
    if (glass && !gGlassReported) {
        NSMutableString *detail = [NSMutableString string];
        [detail appendFormat:@"✅ 液态玻璃已装上\n\n"
                             @"挂载视图：%@\n尺寸：%.0f × %.0f\n系统：iOS %@\n\n"
                             @"继承链：\n%@\n\n%@",
                             NSStringFromClass([bar class]),
                             bar.bounds.size.width, bar.bounds.size.height,
                             [[UIDevice currentDevice] systemVersion],
                             WXARClassChain(bar),
                             WXARDescribeSubviews(bar)];
        // 这一版要确认的只有一件事：走的是哪条分支。
        // 上几版那些子视图/Glass 类清单已经查完，不再重复占屏幕。
        [detail appendFormat:@"\nApp 旧设计兼容模式：%@\n"
                             @"玻璃 effect：%@\n"
                             @"effect 继承链：%@\n"
                             @"玻璃 hidden：%@  alpha：%.2f",
                             WXARAppUsesLegacyDesign()
                                 ? @"是（系统已禁用液态玻璃）" : @"否",
                             glass.effect
                                 ? NSStringFromClass([glass.effect class]) : @"(nil)",
                             glass.effect ? WXARClassChain(glass.effect) : @"-",
                             glass.hidden ? @"是" : @"否", glass.alpha];
        WXARScheduleGlassReport(detail);
    }
}

/// 共用桩：先跑微信原本的布局/初始化，再补上玻璃
static void wxar_tabbar_forward0(id self, SEL _cmd) {
    if (!gGlassTouched) gGlassTouched = [NSMutableSet set];
    @try {
        [gGlassTouched addObject:NSStringFromClass(object_getClass(self))];
    } @catch (NSException *e) { }

    IMP orig = WXAROriginalForClass(object_getClass(self), _cmd);
    if (orig) {
        ((void (*)(id, SEL))orig)(self, _cmd);
    }
    @try {
        WXARApplyGlassToView((UIView *)self);
    } @catch (NSException *e) {
        // 任何异常都不能影响微信本身
    }
}

static int WXARInstallTabBarGlass(void) {
    if (!NSClassFromString(@"UIGlassEffect")) {
        WXARGlassReport(@"❌ 系统没有 UIGlassEffect（低于 iOS 26）\n\n当前系统：%@",
                        [[UIDevice currentDevice] systemVersion]);
        return 0;
    }
    int n = 0;
    // WCTabBarView 是新版微信的底部栏；两个时机都装上，谁先到算谁
    if (WXARInstallForwarder("WCTabBarView", "setupSubviews", (IMP)wxar_tabbar_forward0)) n++;
    if (WXARInstallForwarder("WCTabBarView", "layoutSubviews", (IMP)wxar_tabbar_forward0)) n++;
    // 兼容旧结构
    if (WXARInstallForwarder("MMTabBar", "layoutSubviews", (IMP)wxar_tabbar_forward0)) n++;
    WXARLog(@"底部栏液态玻璃：装了 %d 个钩子", n);

    if (n == 0) {
        WXARGlassReport(@"❌ 一个钩子都没装上\n\n"
                        @"WCTabBarView 类：%@\n"
                        @"MMTabBar 类：%@\n\n"
                        @"说明底部栏的类名和预期不符。",
                        objc_getClass("WCTabBarView") ? @"存在" : @"不存在",
                        objc_getClass("MMTabBar") ? @"存在" : @"不存在");
    }
    return n;
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

static NSString *WXARBuildDiagReport(NSString *bid) {
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"版本 %s\n", WXAR_VERSION];
    [s appendFormat:@"Bundle ID:\n%@\n", bid ? bid : @"(nil)"];
    [s appendFormat:@"%@ / iOS %@\n\n",
        [[UIDevice currentDevice] model], [[UIDevice currentDevice] systemVersion]];

    [s appendFormat:@"✅ 已 Hook (%lu)\n", (unsigned long)gDiagHooked.count];
    if (gDiagHooked.count == 0) [s appendString:@"   一个都没有\n"];
    for (NSString *x in gDiagHooked) [s appendFormat:@"   %@\n", x];

    if (gDiagMissed.count) {
        [s appendFormat:@"\n✗ 未命中 (%lu)\n", (unsigned long)gDiagMissed.count];
        for (NSString *x in gDiagMissed) [s appendFormat:@"   %@\n", x];
    }
    if (gDiagRefused.count) {
        [s appendFormat:@"\n⛔ 被拒绝 (%lu)\n", (unsigned long)gDiagRefused.count];
        for (NSString *x in gDiagRefused) [s appendFormat:@"   %@\n", x];
    }
    return s;
}

/// 判定当前是不是微信进程。
///
/// 早先这里硬编码比对 bundle id == "com.tencent.xin"，结果**改过包名的多开版
/// 微信一进来就被拒了**（真实案例）。改成「能不能找到微信独有的类」来判定：
/// 改包名、改签名都不影响，同时也不会误判到别的 App 上（这些类只有微信有）。
static BOOL WXARIsWeChatProcess(void) {
    static const char *kProbeClasses[] = {
        "MessageRevokeMgr",         // 撤回管理器，8.0.75 实测存在
        "MessageBatchRevokeMgr",
        "CMessageMgr",
        "MessageService",
        "MMServiceCenter",
        "CContactMgr",
        "MMMsgLogic",
    };
    for (size_t i = 0; i < sizeof(kProbeClasses) / sizeof(kProbeClasses[0]); i++) {
        if (objc_getClass(kProbeClasses[i])) return YES;
    }

    // 兜底：包名里带这些关键词也认
    NSString *bid = [[NSBundle mainBundle].bundleIdentifier lowercaseString];
    if (bid) {
        if ([bid containsString:@"tencent"] || [bid containsString:@"wechat"] ||
            [bid containsString:@"weixin"]  || [bid containsString:@"xin"]) {
            return YES;
        }
    }
    return NO;
}

static void WXAREntry(void) {
    @autoreleasepool {
        WXARLogInit();
        WXARDiagInit();

        NSString *bid = [NSBundle mainBundle].bundleIdentifier;

        if (!WXARIsWeChatProcess()) {
            NSLog(@"[anti-revoke] 不是微信进程 (%@)，不启用", bid);
            WXARPopupWhenReady(@"⚠️ 防撤回未启用",
                [NSString stringWithFormat:
                    @"没能在当前进程里找到任何微信独有的类，判定这里不是微信。\n\n"
                    @"Bundle ID：%@\n\n"
                    @"如果这确实是微信，请把这个弹窗内容发给我。",
                    bid ? bid : @"(nil)"], 8);
            return;
        }
        WXARLog(@"确认是微信进程（Bundle ID = %@）", bid);

        // 尽早装「捕获 CMessageMgr」的钩子：必须在它被创建/使用之前装上
        WXARInstallMgrCatcher();

        // 底部栏液态玻璃（iOS 26+ 才生效，低版本自动跳过）
        WXARInstallTabBarGlass();

        // 玻璃诊断：20 秒后若一次都没触发，说明钩子没被调用
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20.0 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), ^{
                @autoreleasepool {
                    if (!gGlassReported) {
                        WXARGlassReport(@"⚠️ 钩子装上了，但一直没被调用\n\n"
                                        @"20 秒内 WCTabBarView 的 setupSubviews / "
                                        @"layoutSubviews 都没触发。\n\n"
                                        @"可能原因：\n"
                                        @"1. 底部栏不是 WCTabBarView\n"
                                        @"2. 你还没切到主界面（微信/通讯录/发现/我）");
                    }
                }
            });

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

        // 所有重试跑完后弹诊断报告（诊断版特有，正式版会去掉）
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(12.0 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), ^{
                @autoreleasepool {
                    WXARPopup(@"微信防撤回 · 诊断报告",
                              WXARBuildDiagReport(bid));
                }
            });

        // 观察模式：必须等候选表的所有重试跑完（最后一轮在 10 秒）之后再装。
        // 否则观察桩会先占住 SEL，导致候选表的「阻止桩」装不上去。
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(11.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                @autoreleasepool {
                    WXARInstallObservers();
                }
            });

        // 顺带在后台跑一次全量扫描，把候选写进日志
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
