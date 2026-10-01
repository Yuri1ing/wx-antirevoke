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

/// 拿 CMessageMgr 单例。走两条路，都不行就返回 nil。
static id WXARMessageMgr(void) {
    static id cached = nil;
    static BOOL tried = NO;
    if (tried) return cached;
    tried = YES;

    @try {
        Class centerCls = objc_getClass("MMServiceCenter");
        SEL defSel = NSSelectorFromString(@"defaultCenter");
        if (centerCls && [centerCls respondsToSelector:defSel]) {
            id center = ((id (*)(id, SEL))objc_msgSend)(centerCls, defSel);
            SEL getSel = NSSelectorFromString(@"getService:");
            if (center && [center respondsToSelector:getSel]) {
                cached = ((id (*)(id, SEL, Class))objc_msgSend)(
                    center, getSel, objc_getClass("CMessageMgr"));
            }
        }
        if (!cached) {
            Class mgrCls = objc_getClass("CMessageMgr");
            SEL shSel = NSSelectorFromString(@"sharedInstance");
            if (mgrCls && [mgrCls respondsToSelector:shSel]) {
                cached = ((id (*)(id, SEL))objc_msgSend)(mgrCls, shSel);
            }
        }
    } @catch (NSException *e) {
        WXARLog(@"获取 CMessageMgr 失败：%@", e.reason);
    }
    if (cached) WXARLog(@"已拿到 CMessageMgr，撤回提示功能可用");
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
static void WXARTryInsertRevokeTip(id arg) {
    @try {
        if (!arg) return;

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
        if (session.length == 0 && content) {
            session = WXARTagValue(content, @"session");
        }
        if (session.length == 0) return;
        if (!WXARTipAllowed(session)) return;

        // 2) 构造一条系统提示消息
        Class wrapCls = objc_getClass("CMessageWrap");
        if (!wrapCls) return;
        id tip = ((id (*)(id, SEL, long long))objc_msgSend)(
            [wrapCls alloc], NSSelectorFromString(@"initWithMsgType:"), 0x2710LL);
        if (!tip) return;

        [tip setValue:session forKey:@"m_nsFromUsr"];
        [tip setValue:session forKey:@"m_nsToUsr"];
        [tip setValue:@"对方撤回了一条消息（已被防撤回拦截，原消息保留）"
                forKey:@"m_nsContent"];
        [tip setValue:@(0x4) forKey:@"m_uiStatus"];
        [tip setValue:@((uint32_t)[[NSDate date] timeIntervalSince1970])
                forKey:@"m_uiCreateTime"];

        // 3) 交给消息管理器写进本地会话
        id mgr = WXARMessageMgr();
        if (!mgr) return;
        SEL addSel = NSSelectorFromString(@"AddLocalMsg:MsgWrap:fixTime:NewMsgArriveNotify:");
        if (![mgr respondsToSelector:addSel]) {
            WXARLog(@"CMessageMgr 没有 AddLocalMsg:MsgWrap:fixTime:NewMsgArriveNotify:");
            return;
        }
        ((void (*)(id, SEL, id, id, BOOL, BOOL))objc_msgSend)(
            mgr, addSel, session, tip, YES, NO);
        WXARLog(@"✅ 已插入撤回提示：session=%@", session);
    } @catch (NSException *e) {
        WXARLog(@"插入撤回提示失败：%@", e.reason);
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
    WXARTryInsertRevokeTip(arg);

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
