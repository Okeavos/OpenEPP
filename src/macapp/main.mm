// Sec menu bar app (macOS). Hosts the agent + real-time monitor in-process and shows a status icon.

#import <Cocoa/Cocoa.h>

#include "agent/agent.h"
#include "agent/detection_store.h"
#include "agent/realtime.h"
#include "common/config.h"
#include "common/log.h"
#include "common/util.h"
#include "monitor/fs_monitor.h"

#include <atomic>
#include <memory>
#include <string>

namespace {

std::unique_ptr<sec::Agent> g_agent;
std::unique_ptr<sec::DetectionStore> g_store;
std::unique_ptr<sec::RealtimeScanner> g_realtime;
sec::FsMonitor g_monitor;
sec::AgentConfig g_config;
bool g_monitor_ok = false;
std::atomic<bool> g_scanning{false};
std::atomic<bool> g_cancel_scan{false};

NSString* ns(const std::string& s) {
    NSString* r = [NSString stringWithUTF8String:s.c_str()];
    return r != nil ? r : @"?";
}

NSString* applescript_escape(NSString* s) {
    NSString* r = [s stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
    return [r stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
}

void post_notification(NSString* title, NSString* body) {
    NSString* src = [NSString stringWithFormat:@"display notification \"%@\" with title \"%@\"",
                                               applescript_escape(body), applescript_escape(title)];
    NSAppleScript* script = [[NSAppleScript alloc] initWithSource:src];
    [script executeAndReturnError:nil];
}

NSString* local_time(const std::string& iso) {
    NSISO8601DateFormatter* in = [[NSISO8601DateFormatter alloc] init];
    NSDate* date = [in dateFromString:ns(iso)];
    if (date == nil) return ns(iso);
    NSDateFormatter* out = [[NSDateFormatter alloc] init];
    out.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    return [out stringFromDate:date];
}

NSString* verdict_label(const std::string& v) {
    if (v == "malicious") return @"악성";
    if (v == "suspicious") return @"의심";
    return ns(v);
}

NSString* action_label(const std::string& a) {
    if (a == "quarantined") return @"격리됨";
    if (a == "quarantine_failed") return @"격리 실패";
    return @"조치 없음";
}

}

@interface SecApp : NSObject <NSApplicationDelegate>
@end

@implementation SecApp {
    NSStatusItem* _item;
    NSMenuItem* _stateItem;
    NSMenuItem* _detailItem;
    NSMenuItem* _scanItem;
    NSMenuItem* _pauseItem;
    NSWindow* _window;
    NSTextView* _text;
    NSTimer* _timer;
    size_t _notified;
}

- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    [self startEngine];
    [self buildStatusItem];
    _timer = [NSTimer timerWithTimeInterval:1.5 target:self selector:@selector(refresh) userInfo:nil repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:_timer forMode:NSRunLoopCommonModes];
    [self refresh];
}

- (void)applicationWillTerminate:(NSNotification*)notification {
    g_cancel_scan = true;
    g_monitor.stop();
    g_realtime.reset();
    g_agent.reset();
    g_store.reset();
}

- (void)startEngine {
    sec::Config cfg;
    cfg.load(sec::AgentConfig::default_data_dir() / "sec.conf");
    g_config = sec::AgentConfig::from_config(cfg);
    if (g_config.scan_paths.empty()) g_config.scan_paths = g_config.watch_paths;

    sec::log::set_console(false);
    sec::log::set_level(sec::log::parse_level(cfg.get("log_level", "info"), sec::log::Level::Info));
    sec::log::set_file(g_config.data_dir / "logs" / "sec.log");

    g_agent = std::make_unique<sec::Agent>(g_config);
    if (!g_agent->initialize()) {
        g_agent.reset();
        return;
    }
    g_store = std::make_unique<sec::DetectionStore>(g_config.data_dir / "detections.tsv");
    g_store->load();
    g_agent->set_detection_store(g_store.get());

    g_realtime = std::make_unique<sec::RealtimeScanner>(*g_agent);
    g_realtime->add_ignore_prefix(g_config.data_dir);
    g_realtime->start();

    if (g_config.realtime_enabled) {
        g_monitor_ok = g_monitor.start(g_config.watch_paths, [](const std::filesystem::path& p) {
            if (g_realtime) g_realtime->notify(p);
        });
        if (!g_monitor_ok) sec::log::error("file monitor failed to start (no watchable folders?)");
    }
    _notified = g_store->total();
    sec::log::info("menu bar app started");
}

- (void)buildStatusItem {
    _item = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];

    NSMenu* menu = [[NSMenu alloc] init];
    menu.autoenablesItems = NO;

    _stateItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    _stateItem.enabled = NO;
    _detailItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    _detailItem.enabled = NO;
    [menu addItem:_stateItem];
    [menu addItem:_detailItem];
    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem* list = [[NSMenuItem alloc] initWithTitle:@"탐지 목록 열기…" action:@selector(openList:) keyEquivalent:@"l"];
    list.target = self;
    list.enabled = YES;
    [menu addItem:list];

    _scanItem = [[NSMenuItem alloc] initWithTitle:@"전체 검사 실행" action:@selector(scanAll:) keyEquivalent:@""];
    _scanItem.target = self;
    _scanItem.enabled = YES;
    [menu addItem:_scanItem];

    _pauseItem = [[NSMenuItem alloc] initWithTitle:@"실시간 보호 일시정지" action:@selector(togglePause:) keyEquivalent:@""];
    _pauseItem.target = self;
    _pauseItem.enabled = YES;
    [menu addItem:_pauseItem];

    [menu addItem:[NSMenuItem separatorItem]];

    NSMenuItem* folder = [[NSMenuItem alloc] initWithTitle:@"데이터 폴더 열기" action:@selector(openDataFolder:) keyEquivalent:@""];
    folder.target = self;
    folder.enabled = YES;
    [menu addItem:folder];

    NSMenuItem* quit = [[NSMenuItem alloc] initWithTitle:@"Sec 종료" action:@selector(quit:) keyEquivalent:@"q"];
    quit.target = self;
    quit.enabled = YES;
    [menu addItem:quit];

    _item.menu = menu;
}

- (void)applyIcon:(NSString*)symbol tint:(NSColor*)tint fallback:(NSString*)fallback {
    NSStatusBarButton* button = _item.button;
    NSImage* img = nil;
    if (@available(macOS 11.0, *)) {
        img = [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:@"Sec"];
    }
    if (img != nil) {
        [img setTemplate:YES];
        button.image = img;
        button.title = @"";
        button.contentTintColor = tint;
    } else {
        button.image = nil;
        button.title = fallback;
    }
}

- (void)refresh {
    if (!g_agent || !g_store || !g_realtime) {
        [self applyIcon:@"exclamationmark.triangle" tint:NSColor.systemOrangeColor fallback:@"Sec ⚠"];
        _stateItem.title = @"⚠ 에이전트 초기화 실패 (로그 확인)";
        _detailItem.title = ns(sec::util::path_to_utf8(g_config.data_dir / "logs" / "sec.log"));
        return;
    }

    const size_t total = g_store->total();
    const size_t unseen = g_store->unseen();
    const sec::RealtimeStats st = g_realtime->stats();
    const bool paused = g_realtime->paused();

    NSString* symbol = nil;
    NSColor* tint = nil;
    NSString* fallback = nil;
    NSString* state = nil;
    if (unseen > 0) {
        symbol = @"exclamationmark.shield.fill";
        tint = NSColor.systemRedColor;
        fallback = @"Sec !";
        state = [NSString stringWithFormat:@"⚠ 새 탐지 %zu건 — 목록을 확인하세요", unseen];
    } else if (!g_config.realtime_enabled) {
        symbol = @"shield.slash";
        fallback = @"Sec ○";
        state = @"○ 실시간 보호 꺼짐 (설정)";
    } else if (paused) {
        symbol = @"shield.slash";
        fallback = @"Sec ⏸";
        state = @"⏸ 실시간 보호 일시정지";
    } else if (!g_monitor_ok) {
        symbol = @"shield.slash";
        tint = NSColor.systemOrangeColor;
        fallback = @"Sec ⚠";
        state = @"⚠ 폴더 감시 시작 실패 (폴더 접근 권한 확인)";
    } else {
        symbol = @"checkmark.shield";
        fallback = @"Sec ✓";
        state = @"● 실시간 보호 중";
    }
    [self applyIcon:symbol tint:tint fallback:fallback];
    _item.button.toolTip = state;

    _stateItem.title = state;
    _detailItem.title = [NSString stringWithFormat:@"누적 탐지 %zu건 · 실시간 검사 %llu개", total,
                                                   (unsigned long long)st.scanned];
    _pauseItem.title = paused ? @"실시간 보호 재개" : @"실시간 보호 일시정지";

    if (total > _notified) {
        const auto recent = g_store->recent();
        const size_t added = total - _notified;
        if (!recent.empty()) {
            const auto& r = recent.front();
            NSString* body = [NSString stringWithFormat:@"%@ · %@\n%@", verdict_label(r.verdict), ns(r.threat),
                                                        ns(r.path)];
            post_notification(added > 1 ? [NSString stringWithFormat:@"Sec: 새 탐지 %zu건", added] : @"Sec: 위협 탐지", body);
        }
        _notified = total;
    }

    if (_window != nil && _window.visible) [self reloadText];
}

- (void)buildWindow {
    NSRect frame = NSMakeRect(0, 0, 700, 460);
    _window = [[NSWindow alloc] initWithContentRect:frame
                                          styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                     NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable)
                                            backing:NSBackingStoreBuffered
                                              defer:NO];
    _window.title = @"Sec — 탐지 목록";
    [_window setReleasedWhenClosed:NO];
    [_window center];

    NSScrollView* scroll = [[NSScrollView alloc] initWithFrame:frame];
    scroll.hasVerticalScroller = YES;
    scroll.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

    _text = [[NSTextView alloc] initWithFrame:frame];
    _text.editable = NO;
    _text.font = [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];
    _text.textContainerInset = NSMakeSize(10, 10);
    _text.minSize = NSMakeSize(0, 0);
    _text.maxSize = NSMakeSize(CGFLOAT_MAX, CGFLOAT_MAX);
    _text.verticallyResizable = YES;
    _text.horizontallyResizable = NO;
    _text.autoresizingMask = NSViewWidthSizable;
    _text.textContainer.widthTracksTextView = YES;

    scroll.documentView = _text;
    _window.contentView = scroll;
}

- (void)reloadText {
    if (_text == nil || !g_store) return;
    NSMutableString* s = [NSMutableString string];
    const auto records = g_store->recent();
    if (records.empty()) {
        [s appendString:@"✅ 탐지된 항목이 없습니다.\n\n"];
        [s appendString:@"감시 중인 폴더:\n"];
        for (const auto& p : g_config.watch_paths) [s appendFormat:@"  %@\n", ns(sec::util::path_to_utf8(p))];
    } else {
        [s appendFormat:@"누적 탐지 %zu건 (최근 %zu건 표시)\n\n", g_store->total(), records.size()];
        for (const auto& r : records) {
            [s appendFormat:@"[%@] %@  %@\n", local_time(r.time), verdict_label(r.verdict), ns(r.threat)];
            [s appendFormat:@"  %@\n", ns(r.path)];
            [s appendFormat:@"  조치: %@   점수 %d   sha256 %@\n\n", action_label(r.action), r.score,
                            ns(r.sha256.substr(0, 16))];
        }
    }
    if (![s isEqualToString:_text.string]) _text.string = s;
}

- (void)openList:(id)sender {
    if (_window == nil) [self buildWindow];
    if (g_store) g_store->mark_seen();
    [self reloadText];
    [self refresh];
    [NSApp activateIgnoringOtherApps:YES];
    [_window makeKeyAndOrderFront:nil];
}

- (void)scanAll:(id)sender {
    if (!g_agent || g_scanning.exchange(true)) return;
    _scanItem.title = @"전체 검사 중…";
    _scanItem.enabled = NO;
    __weak SecApp* weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        g_cancel_scan = false;
        const sec::ScanSummary sum = g_agent ? g_agent->scan_now(&g_cancel_scan) : sec::ScanSummary();
        dispatch_async(dispatch_get_main_queue(), ^{
            g_scanning = false;
            SecApp* self2 = weakSelf;
            if (self2 == nil) return;
            self2->_scanItem.title = @"전체 검사 실행";
            self2->_scanItem.enabled = YES;
            post_notification(@"Sec 전체 검사 완료",
                              [NSString stringWithFormat:@"검사 %llu개 · 악성 %llu · 의심 %llu",
                                                         (unsigned long long)sum.scanned,
                                                         (unsigned long long)sum.malicious,
                                                         (unsigned long long)sum.suspicious]);
        });
    });
}

- (void)togglePause:(id)sender {
    if (g_realtime) g_realtime->set_paused(!g_realtime->paused());
    [self refresh];
}

- (void)openDataFolder:(id)sender {
    NSURL* url = [NSURL fileURLWithPath:ns(sec::util::path_to_utf8(g_config.data_dir))];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

- (void)quit:(id)sender {
    [NSApp terminate:nil];
}

@end

static SecApp* g_delegate = nil;

int main(int argc, const char* argv[]) {
    (void)argc;
    (void)argv;
    @autoreleasepool {
        NSApplication* app = [NSApplication sharedApplication];
        g_delegate = [[SecApp alloc] init];
        app.delegate = g_delegate;
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [app run];
    }
    return 0;
}
