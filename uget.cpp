// uget.cpp v4.1 - Immortal Multi-Mirror CLI Downloader with SHA-256 & Quiet Mode
// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: (C) 2026 mukyokyo
//
// Build (UCRT64): g++ -O2 -s -static uget.cpp -lwinhttp -lbcrypt -o uget.exe

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <winioctl.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <clocale>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL 133
#endif
#ifndef WINHTTP_PROTOCOL_FLAG_HTTP2
#define WINHTTP_PROTOCOL_FLAG_HTTP2 0x1
#endif
#ifndef WINHTTP_QUERY_ETAG
#define WINHTTP_QUERY_ETAG 54
#endif
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

constexpr uint64_t kUnknownEnd = UINT64_MAX;
constexpr size_t kIoBufSize = 128 * 1024;
constexpr uint64_t kTailMinSplit = 2ULL * 1024 * 1024;
constexpr uint32_t kMetaMagic = 0x34544755;  // "UGT4"
constexpr int kMetaSaveTicks = 4;            // x 500 ms
constexpr double kMiB = 1024.0 * 1024.0;
constexpr size_t kSidecarLimit = 1024 * 1024;

// A split point is always at least kTailMinSplit past the committed position,
// so one in-flight write can never cross it.
static_assert(kTailMinSplit >= 4 * kIoBufSize, "split floor must exceed one in-flight write");

struct Config {
  std::vector<std::wstring> urls;
  std::wstring output;
  std::wstring expected_sha256;  // 64-char hex, "print", or empty
  bool sha_sidecar = true;
  int threads = 8;
  int max_giveup_streak = 25;  // 0 = infinite
  int timeout_sec = 15;
  uint64_t min_speed_bps = 1024;  // 0 = disabled
  uint64_t min_split = 16ULL * 1024 * 1024;
  bool insecure = false;
  bool http2 = false;
  bool quiet = false;
  bool is_tty = true;
};

struct Segment {
  uint64_t current;  // committed (written) position
  uint64_t end;
  bool active;
};

struct MirrorState {
  std::wstring original_url;
  std::wstring direct_url;
  bool dead = false;
  int active_workers = 0;
  int fail_count = 0;
  double ema_speed_bps = 2.0 * 1024.0 * 1024.0;
  std::chrono::steady_clock::time_point cooldown_until{};
  std::chrono::steady_clock::time_point next_connect_allowed{};
};

struct MetaIdentity {
  uint64_t total_size = 0;
  std::wstring origin_url;
  std::wstring validator;
};

#pragma pack(push, 1)
struct MetaHeader {
  uint32_t magic;
  uint64_t total_size;
  uint32_t seg_count;
  uint32_t url_len;
  uint32_t validator_len;
};
struct MetaSegment {
  uint64_t current;
  uint64_t end;
};
#pragma pack(pop)

enum class StopReason : int { None = 0, User, GiveUp, NoMirrors, DiskError };

static std::atomic<bool> g_stop{false};
static std::atomic<bool> g_done{false};
static std::atomic<int> g_stop_reason{0};
static std::atomic<bool> g_user_abort{false};
static std::atomic<uint64_t> g_total_retries{0};
static std::atomic<int> g_fail_streak{0};
static std::atomic<int> g_allowed_workers{8};
static std::atomic<int> g_running_workers{0};

static std::mutex g_cv_mutex;
static std::condition_variable g_cv;

static std::mutex g_seg_mutex;
static std::vector<Segment> g_segments;

static std::mutex g_mirror_mutex;
static std::vector<MirrorState> g_mirrors;

static std::mutex g_handle_mutex;
static std::vector<HINTERNET> g_active_handles;

static bool g_quiet = false;

void LogInfo(const char* fmt, ...) {
  if (g_quiet) return;
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  fflush(stdout);
}

void LogInfoW(const wchar_t* fmt, ...) {
  if (g_quiet) return;
  va_list args;
  va_start(args, fmt);
  vwprintf(fmt, args);
  va_end(args);
  fflush(stdout);
}

bool ShouldQuit() { return g_stop.load() || g_done.load(); }

// Handles created after stop/done are closed immediately, so a stale handle value
// held by a worker can never alias a newly registered one.
void RegisterHandle(HINTERNET& h) {
  if (!h) return;
  {
    std::lock_guard<std::mutex> lk(g_handle_mutex);
    if (!ShouldQuit()) {
      g_active_handles.push_back(h);
      return;
    }
  }
  WinHttpCloseHandle(h);
  h = nullptr;
}

void CloseAndUnregisterHandle(HINTERNET& h) {
  if (!h) return;
  HINTERNET target = nullptr;
  {
    std::lock_guard<std::mutex> lk(g_handle_mutex);
    auto it = std::find(g_active_handles.begin(), g_active_handles.end(), h);
    if (it != g_active_handles.end()) {
      target = *it;
      g_active_handles.erase(it);
    }
  }
  h = nullptr;
  if (target) WinHttpCloseHandle(target);
}

void AbortAllActiveHandles() {
  std::vector<HINTERNET> to_close;
  {
    std::lock_guard<std::mutex> lk(g_handle_mutex);
    to_close.swap(g_active_handles);
  }
  for (HINTERNET h : to_close) {
    if (h) WinHttpCloseHandle(h);
  }
}

void WakeAll() {
  { std::lock_guard<std::mutex> lk(g_cv_mutex); }
  g_cv.notify_all();
}

bool InterruptibleSleep(int ms) {
  if (ms > 0 && !ShouldQuit()) {
    std::unique_lock<std::mutex> lk(g_cv_mutex);
    g_cv.wait_for(lk, std::chrono::milliseconds(ms), ShouldQuit);
  }
  return !ShouldQuit();
}

void TriggerStop(StopReason reason) {
  int expected = (int)StopReason::None;
  g_stop_reason.compare_exchange_strong(expected, (int)reason);
  g_stop.store(true);
  WakeAll();
  AbortAllActiveHandles();
}

void MarkDone() {
  g_done.store(true);
  WakeAll();
  AbortAllActiveHandles();
}

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl_type) {
  if (ctrl_type != CTRL_C_EVENT && ctrl_type != CTRL_BREAK_EVENT && ctrl_type != CTRL_CLOSE_EVENT) return FALSE;
  if (g_user_abort.exchange(true)) TerminateProcess(GetCurrentProcess(), 130);
  TriggerStop(StopReason::User);
  std::thread([] {
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    TerminateProcess(GetCurrentProcess(), 130);
  }).detach();
  return TRUE;
}

struct ParsedUrl {
  bool https = false;
  INTERNET_PORT port = 0;
  std::wstring host;
  std::wstring path_and_query;
};

bool ParseUrl(const std::wstring& url, ParsedUrl& out) {
  URL_COMPONENTS uc{};
  uc.dwStructSize = sizeof(uc);
  uc.dwSchemeLength = (DWORD)-1;
  uc.dwHostNameLength = (DWORD)-1;
  uc.dwUrlPathLength = (DWORD)-1;
  uc.dwExtraInfoLength = (DWORD)-1;

  if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) return false;
  out.https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
  out.port = uc.nPort;
  out.host.assign(uc.lpszHostName, uc.dwHostNameLength);
  out.path_and_query.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
  if (uc.dwExtraInfoLength > 0) {
    out.path_and_query.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
  }
  if (out.path_and_query.empty()) out.path_and_query = L"/";
  return true;
}

std::wstring ToLower(std::wstring s) {
  for (wchar_t& c : s) c = (wchar_t)towlower(c);
  return s;
}

int HexDigit(wchar_t c) {
  if (c >= L'0' && c <= L'9') return c - L'0';
  if (c >= L'a' && c <= L'f') return c - L'a' + 10;
  if (c >= L'A' && c <= L'F') return c - L'A' + 10;
  return -1;
}

bool PercentDecodeUtf8(const std::wstring& in, std::wstring& out) {
  std::string bytes;
  bytes.reserve(in.size());
  for (size_t i = 0; i < in.size(); ++i) {
    const wchar_t c = in[i];
    if (c == L'%' && i + 2 < in.size()) {
      const int hi = HexDigit(in[i + 1]);
      const int lo = HexDigit(in[i + 2]);
      if (hi >= 0 && lo >= 0) {
        bytes.push_back((char)(hi * 16 + lo));
        i += 2;
        continue;
      }
    }
    if (c >= 0x80) return false;
    bytes.push_back((char)c);
  }
  if (bytes.empty()) {
    out.clear();
    return true;
  }
  const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), (int)bytes.size(), nullptr, 0);
  if (n <= 0) return false;
  out.assign(n, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), (int)bytes.size(), out.data(), n);
  return true;
}

std::wstring SanitizeFilename(std::wstring name) {
  const size_t slash = name.find_last_of(L"/\\");
  if (slash != std::wstring::npos) name.erase(0, slash + 1);

  for (wchar_t& c : name) {
    if (c < 32 || wcschr(L"<>:\"/\\|?*", c) != nullptr) c = L'_';
  }
  while (!name.empty() && (name.back() == L'.' || name.back() == L' ')) name.pop_back();
  const size_t lead = name.find_first_not_of(L' ');
  name.erase(0, lead == std::wstring::npos ? name.size() : lead);
  if (name.empty()) return L"download.bin";

  const std::wstring stem = ToLower(name.substr(0, name.find(L'.')));
  const bool reserved = stem == L"con" || stem == L"prn" || stem == L"aux" || stem == L"nul" ||
                        (stem.size() == 4 && (stem.compare(0, 3, L"com") == 0 || stem.compare(0, 3, L"lpt") == 0) &&
                         stem[3] >= L'1' && stem[3] <= L'9');
  return reserved ? L"_" + name : name;
}

std::wstring FilenameFromUrl(std::wstring url) {
  const size_t cut = url.find_first_of(L"?#");
  if (cut != std::wstring::npos) url.resize(cut);
  const size_t scheme = url.find(L"://");
  if (url.find(L'/', scheme == std::wstring::npos ? 0 : scheme + 3) == std::wstring::npos) return L"";
  const std::wstring name = url.substr(url.find_last_of(L'/') + 1);
  std::wstring decoded;
  return PercentDecodeUtf8(name, decoded) ? decoded : name;
}

std::wstring QueryHeader(HINTERNET hReq, DWORD info) {
  DWORD sz = 0;
  if (WinHttpQueryHeaders(hReq, info, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &sz, WINHTTP_NO_HEADER_INDEX) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER || sz == 0) {
    return L"";
  }
  std::wstring v(sz / sizeof(wchar_t), L'\0');
  if (!WinHttpQueryHeaders(hReq, info, WINHTTP_HEADER_NAME_BY_INDEX, v.data(), &sz, WINHTTP_NO_HEADER_INDEX)) return L"";
  v.resize(sz / sizeof(wchar_t));
  return v;
}

DWORD QueryStatus(HINTERNET hReq) {
  DWORD status = 0, sz = sizeof(status);
  WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                      WINHTTP_NO_HEADER_INDEX);
  return status;
}

bool QueryContentLength(HINTERNET hReq, uint64_t& out) {
  const std::wstring v = QueryHeader(hReq, WINHTTP_QUERY_CONTENT_LENGTH);
  if (v.empty()) return false;
  wchar_t* endp = nullptr;
  const uint64_t n = std::wcstoull(v.c_str(), &endp, 10);
  if (endp == v.c_str()) return false;
  out = n;
  return true;
}

struct ContentRange {
  bool valid = false;
  bool has_total = false;
  uint64_t start = 0;
  uint64_t last = 0;
  uint64_t total = 0;
};

ContentRange QueryContentRange(HINTERNET hReq) {
  ContentRange cr;
  const std::wstring v = QueryHeader(hReq, WINHTTP_QUERY_CONTENT_RANGE);
  const size_t sp = v.find(L' ');
  if (sp == std::wstring::npos) return cr;
  const size_t dash = v.find(L'-', sp);
  if (dash == std::wstring::npos) return cr;
  const size_t slash = v.find(L'/', dash);
  if (slash == std::wstring::npos) return cr;

  const wchar_t* base = v.c_str();
  wchar_t* endp = nullptr;
  cr.start = std::wcstoull(base + sp + 1, &endp, 10);
  if (endp != base + dash) return cr;
  cr.last = std::wcstoull(base + dash + 1, &endp, 10);
  if (endp != base + slash) return cr;
  if (base[slash + 1] != L'*') {
    cr.total = std::wcstoull(base + slash + 1, &endp, 10);
    cr.has_total = (endp != base + slash + 1);
  }
  cr.valid = cr.last >= cr.start;
  return cr;
}

std::wstring QueryValidator(HINTERNET hReq) {
  const std::wstring lm = QueryHeader(hReq, WINHTTP_QUERY_LAST_MODIFIED);
  if (!lm.empty()) return L"LM:" + lm;
  const std::wstring et = QueryHeader(hReq, WINHTTP_QUERY_ETAG);
  if (!et.empty()) return L"ET:" + et;
  return L"";
}

std::wstring GetFinalUrlFromRequest(HINTERNET hReq, const std::wstring& fallback_url) {
  DWORD sz = 0;
  WinHttpQueryOption(hReq, WINHTTP_OPTION_URL, nullptr, &sz);
  if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && sz > 0) {
    std::wstring final_url(sz / sizeof(wchar_t), L'\0');
    if (WinHttpQueryOption(hReq, WINHTTP_OPTION_URL, final_url.data(), &sz)) {
      while (!final_url.empty() && final_url.back() == L'\0') final_url.pop_back();
      if (!final_url.empty()) return final_url;
    }
  }
  return fallback_url;
}

std::wstring ContentDispositionParam(const std::wstring& cd, const std::wstring& key) {
  const std::wstring lower = ToLower(cd);
  const std::wstring needle = key + L"=";
  for (size_t pos = lower.find(needle); pos != std::wstring::npos; pos = lower.find(needle, pos + 1)) {
    if (pos > 0 && wcschr(L"; \t", lower[pos - 1]) == nullptr) continue;
    const size_t v = cd.find_first_not_of(L" \t", pos + needle.size());
    if (v == std::wstring::npos) return L"";
    if (cd[v] == L'"') {
      const size_t e = cd.find(L'"', v + 1);
      return cd.substr(v + 1, e == std::wstring::npos ? std::wstring::npos : e - v - 1);
    }
    const size_t e = cd.find_first_of(L"; \t\r\n", v);
    return cd.substr(v, e == std::wstring::npos ? std::wstring::npos : e - v);
  }
  return L"";
}

std::wstring ExtractFilename(HINTERNET hReq, const std::wstring& final_url) {
  std::wstring name;
  const std::wstring cd = QueryHeader(hReq, WINHTTP_QUERY_CONTENT_DISPOSITION);
  if (!cd.empty()) {
    const std::wstring ext = ContentDispositionParam(cd, L"filename*");
    const size_t q1 = ext.find(L'\'');
    const size_t q2 = (q1 == std::wstring::npos) ? q1 : ext.find(L'\'', q1 + 1);
    if (q2 != std::wstring::npos && ToLower(ext.substr(0, q1)) == L"utf-8") {
      PercentDecodeUtf8(ext.substr(q2 + 1), name);
    }
    if (name.empty()) name = ContentDispositionParam(cd, L"filename");
  }
  if (name.empty()) name = FilenameFromUrl(final_url);
  return SanitizeFilename(name);
}

void ApplyRequestOptions(HINTERNET hReq, const Config& cfg, bool is_https) {
  if (cfg.http2) {
    DWORD proto = WINHTTP_PROTOCOL_FLAG_HTTP2;
    WinHttpSetOption(hReq, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &proto, sizeof(proto));
  }
  if (cfg.insecure && is_https) {
    DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
  }
}

HINTERNET OpenGetRequest(HINTERNET hConn, const ParsedUrl& pu, const Config& cfg, bool refresh) {
  const DWORD flags = (pu.https ? WINHTTP_FLAG_SECURE : 0) | (refresh ? WINHTTP_FLAG_REFRESH : 0);
  HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", pu.path_and_query.c_str(), nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  RegisterHandle(hReq);
  if (hReq) ApplyRequestOptions(hReq, cfg, pu.https);
  return hReq;
}

bool SendAndReceive(HINTERNET hReq, const std::wstring& headers) {
  const wchar_t* h = headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str();
  const DWORD len = headers.empty() ? 0 : (DWORD)-1L;
  return WinHttpSendRequest(hReq, h, len, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(hReq, nullptr);
}

struct ProbeResult {
  bool ok = false;
  bool supports_range = false;
  bool size_known = false;
  uint64_t total_size = 0;
  std::wstring filename;
  std::wstring origin_url;
  std::wstring validator;
};

// Prefers a mirror that serves ranges with a known total; otherwise falls back
// to the first mirror that answered at all (sequential mode).
ProbeResult ProbeMirrors(HINTERNET hSession, const Config& cfg) {
  for (int attempt = 1; !g_stop.load(); ++attempt) {
    ProbeResult fallback;
    bool any_alive = false;

    for (size_t i = 0; i < g_mirrors.size() && !g_stop.load(); ++i) {
      MirrorState& m = g_mirrors[i];
      if (m.dead) continue;
      ParsedUrl pu;
      if (!ParseUrl(m.original_url, pu)) {
        fwprintf(stderr, L"[!] Invalid URL skipped: %ls\n", m.original_url.c_str());
        m.dead = true;
        continue;
      }
      any_alive = true;

      HINTERNET hConn = WinHttpConnect(hSession, pu.host.c_str(), pu.port, 0);
      RegisterHandle(hConn);
      HINTERNET hReq = hConn ? OpenGetRequest(hConn, pu, cfg, true) : nullptr;

      ProbeResult r;
      if (hReq && SendAndReceive(hReq, L"Range: bytes=0-0\r\n")) {
        const DWORD status = QueryStatus(hReq);
        if (status == 200 || status == 206 || status == 416) {
          r.ok = true;
          if (status == 206) {
            const ContentRange cr = QueryContentRange(hReq);
            if (cr.valid && cr.start == 0 && cr.has_total && cr.total > 0) {
              r.supports_range = true;
              r.size_known = true;
              r.total_size = cr.total;
            }
          } else if (status == 200) {
            r.size_known = QueryContentLength(hReq, r.total_size);
          }
          const std::wstring final_url = GetFinalUrlFromRequest(hReq, m.original_url);
          r.filename = ExtractFilename(hReq, final_url);
          r.origin_url = m.original_url;
          r.validator = QueryValidator(hReq);
          m.direct_url = final_url;
        } else {
          LogInfo("[!] Mirror #%zu: HTTP %lu\n", i + 1, status);
        }
      }
      CloseAndUnregisterHandle(hReq);
      CloseAndUnregisterHandle(hConn);

      if (r.ok && r.supports_range) return r;
      if (r.ok && !fallback.ok) fallback = std::move(r);
    }

    if (fallback.ok) return fallback;
    if (!any_alive || g_stop.load()) break;
    if (cfg.max_giveup_streak > 0 && attempt >= cfg.max_giveup_streak) break;
    g_total_retries.fetch_add(1);
    InterruptibleSleep(std::min(1000 * attempt, 5000));
  }
  return ProbeResult{};
}

bool IsSha256Hex(const std::wstring& s) {
  return s.size() == 64 && s.find_first_not_of(L"0123456789abcdefABCDEF") == std::wstring::npos;
}

std::wstring Trim(const std::wstring& s) {
  const size_t b = s.find_first_not_of(L" \t\r");
  if (b == std::wstring::npos) return L"";
  return s.substr(b, s.find_last_not_of(L" \t\r") - b + 1);
}

std::wstring BaseName(const std::wstring& p) {
  const size_t s = p.find_last_of(L"/\\");
  return s == std::wstring::npos ? p : p.substr(s + 1);
}

enum class FetchResult { Ok, Unusable, Unreachable };

FetchResult FetchSmallText(HINTERNET hSession, const Config& cfg, const std::wstring& url, size_t limit, std::string& out) {
  ParsedUrl pu;
  if (!ParseUrl(url, pu)) return FetchResult::Unusable;
  HINTERNET hConn = WinHttpConnect(hSession, pu.host.c_str(), pu.port, 0);
  RegisterHandle(hConn);
  HINTERNET hReq = hConn ? OpenGetRequest(hConn, pu, cfg, true) : nullptr;

  FetchResult r = FetchResult::Unreachable;
  if (hReq && SendAndReceive(hReq, L"")) {
    r = FetchResult::Unusable;
    uint64_t len = 0;
    if (QueryStatus(hReq) == 200 && !(QueryContentLength(hReq, len) && len > limit)) {
      out.clear();
      char buf[16384];
      bool eof = false;
      for (;;) {
        DWORD got = 0;
        if (!WinHttpReadData(hReq, buf, sizeof(buf), &got)) break;
        if (got == 0) {
          eof = true;
          break;
        }
        if (out.size() + got > limit) break;
        out.append(buf, got);
      }
      if (eof && !out.empty()) r = FetchResult::Ok;
    }
  }
  CloseAndUnregisterHandle(hReq);
  CloseAndUnregisterHandle(hConn);
  return r;
}

struct ShaEntry {
  std::wstring hash;
  std::wstring name;
};

// Accepts GNU ("hash  name", "hash *name", bare hash) and BSD ("SHA256 (name) = hash") lines.
// Any other non-comment line rejects the whole body, which filters out soft-404 HTML pages.
bool ParseShaList(const std::string& body, std::vector<ShaEntry>& out) {
  out.clear();
  if (body.find('\0') != std::string::npos) return false;
  const size_t bom = body.compare(0, 3, "\xEF\xBB\xBF") == 0 ? 3 : 0;
  const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, body.data() + bom, (int)(body.size() - bom), nullptr, 0);
  if (n <= 0) return false;
  std::wstring text(n, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, body.data() + bom, (int)(body.size() - bom), text.data(), n);

  for (size_t start = 0; start < text.size();) {
    size_t nl = text.find(L'\n', start);
    if (nl == std::wstring::npos) nl = text.size();
    std::wstring line = Trim(text.substr(start, nl - start));
    start = nl + 1;
    if (line.empty() || line[0] == L'#') continue;
    if (line[0] == L'\\') line.erase(0, 1);

    ShaEntry e;
    if (line.size() >= 64 && IsSha256Hex(line.substr(0, 64)) &&
        (line.size() == 64 || line[64] == L' ' || line[64] == L'\t')) {
      e.hash = line.substr(0, 64);
      size_t p = line.find_first_not_of(L" \t", 64);
      if (p != std::wstring::npos) {
        if (line[p] == L'*') ++p;
        e.name = line.substr(p);
      }
    } else if (line.compare(0, 6, L"SHA256") == 0) {
      const size_t lp = line.find(L'(');
      const size_t rp = line.rfind(L')');
      const size_t eq = line.rfind(L'=');
      if (lp == std::wstring::npos || line.find_first_not_of(L' ', 6) != lp || rp == std::wstring::npos || rp < lp ||
          eq == std::wstring::npos || eq < rp) {
        return false;
      }
      e.hash = Trim(line.substr(eq + 1));
      e.name = line.substr(lp + 1, rp - lp - 1);
      if (!IsSha256Hex(e.hash)) return false;
    } else {
      return false;
    }
    e.hash = ToLower(e.hash);
    out.push_back(std::move(e));
  }
  return !out.empty();
}

bool PickSha(const std::vector<ShaEntry>& entries, const std::vector<std::wstring>& names, bool per_file, std::wstring& out) {
  if (per_file && entries.size() == 1) {
    out = entries[0].hash;
    return true;
  }
  std::wstring found;
  for (const auto& e : entries) {
    const std::wstring b = ToLower(BaseName(e.name));
    if (b.empty()) continue;
    for (const auto& n : names) {
      if (n.empty() || ToLower(n) != b) continue;
      if (!found.empty() && found != e.hash) return false;
      found = e.hash;
    }
  }
  if (found.empty()) return false;
  out = found;
  return true;
}

struct SidecarCandidate {
  std::wstring url;
  bool per_file;
};

std::vector<SidecarCandidate> SidecarCandidates(const std::wstring& url) {
  const std::wstring base = url.substr(0, url.find_first_of(L"?#"));
  const size_t scheme = base.find(L"://");
  if (base.find(L'/', scheme == std::wstring::npos ? 0 : scheme + 3) == std::wstring::npos) return {};
  const size_t last = base.find_last_of(L'/');
  std::vector<SidecarCandidate> out;
  if (last + 1 < base.size()) {
    out.push_back({base + L".sha256", true});
    out.push_back({base + L".sha256sum", true});
  }
  const std::wstring dir = base.substr(0, last + 1);
  out.push_back({dir + L"SHA256SUMS", false});
  out.push_back({dir + L"sha256sums.txt", false});
  return out;
}

// Best effort: one request per candidate, and an unreachable host skips to the next mirror.
std::wstring FindSidecarSha256(HINTERNET hSession, const Config& cfg, const ProbeResult& probe, std::wstring& source) {
  std::vector<std::wstring> urls{probe.origin_url};
  for (const auto& m : g_mirrors) {
    if (!m.dead && m.original_url != probe.origin_url) urls.push_back(m.original_url);
  }
  for (const auto& url : urls) {
    const std::vector<std::wstring> names{FilenameFromUrl(url), probe.filename};
    for (const auto& cand : SidecarCandidates(url)) {
      if (g_stop.load()) return L"";
      std::string body;
      std::vector<ShaEntry> entries;
      std::wstring hash;
      const FetchResult r = FetchSmallText(hSession, cfg, cand.url, kSidecarLimit, body);
      if (r == FetchResult::Unreachable) break;
      if (r == FetchResult::Ok && ParseShaList(body, entries) && PickSha(entries, names, cand.per_file, hash)) {
        source = cand.url;
        return hash;
      }
    }
  }
  return L"";
}

bool SelectAndPaceMirror(int worker_id, size_t& out_mirror_idx, std::wstring& out_target_url, bool& out_is_refresh) {
  int wait_ms = 0;
  {
    std::lock_guard<std::mutex> lk(g_mirror_mutex);
    const auto now = std::chrono::steady_clock::now();

    size_t best_idx = SIZE_MAX;
    double best_score = -1.0;

    for (size_t i = 0; i < g_mirrors.size(); ++i) {
      const auto& m = g_mirrors[i];
      if (m.dead || now < m.cooldown_until) continue;
      double score = m.ema_speed_bps / ((m.active_workers + 1.0) * (1.0 + m.fail_count * 0.75));
      if ((size_t)worker_id % g_mirrors.size() == i) score *= 1.15;
      if (score > best_score) {
        best_score = score;
        best_idx = i;
      }
    }

    if (best_idx == SIZE_MAX) {
      auto earliest = std::chrono::steady_clock::time_point::max();
      for (size_t i = 0; i < g_mirrors.size(); ++i) {
        if (!g_mirrors[i].dead && g_mirrors[i].cooldown_until < earliest) {
          earliest = g_mirrors[i].cooldown_until;
          best_idx = i;
        }
      }
    }

    if (best_idx == SIZE_MAX) return false;

    MirrorState& chosen = g_mirrors[best_idx];
    chosen.active_workers++;

    const auto ready_time = std::max(chosen.cooldown_until, chosen.next_connect_allowed);
    if (now < ready_time) {
      wait_ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(ready_time - now).count();
    }
    chosen.next_connect_allowed = std::max(now, ready_time) + std::chrono::milliseconds(220);

    out_mirror_idx = best_idx;
    out_is_refresh = chosen.direct_url.empty();
    out_target_url = out_is_refresh ? chosen.original_url : chosen.direct_url;
  }

  if (wait_ms > 0) return InterruptibleSleep(wait_ms);
  return !ShouldQuit();
}

void ReleaseMirrorWorker(size_t mirror_idx, uint64_t bytes_transferred, double elapsed_sec, bool had_error) {
  std::lock_guard<std::mutex> lk(g_mirror_mutex);
  if (mirror_idx >= g_mirrors.size()) return;
  MirrorState& m = g_mirrors[mirror_idx];
  if (m.active_workers > 0) m.active_workers--;

  if (bytes_transferred >= 65536 && elapsed_sec > 0.05) {
    const double inst_bps = (double)bytes_transferred / elapsed_sec;
    m.ema_speed_bps = m.ema_speed_bps * 0.7 + inst_bps * 0.3;
  }
  if (!had_error && bytes_transferred > 0) m.fail_count = 0;
}

void PenalizeMirror(size_t mirror_idx, int status_code, HINTERNET hReq, bool expire_direct_url) {
  int cooldown_ms = (status_code == 429 || status_code == 503) ? 4000 : 1500;
  if (hReq) {
    wchar_t ra_buf[64] = {};
    DWORD ra_sz = sizeof(ra_buf);
    if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RETRY_AFTER, WINHTTP_HEADER_NAME_BY_INDEX, ra_buf, &ra_sz,
                            WINHTTP_NO_HEADER_INDEX)) {
      const int sec = _wtoi(ra_buf);
      if (sec > 0 && sec <= 120) cooldown_ms = sec * 1000;
    }
  }

  bool all_throttled = true;
  {
    std::lock_guard<std::mutex> lk(g_mirror_mutex);
    const auto now = std::chrono::steady_clock::now();
    if (mirror_idx < g_mirrors.size()) {
      MirrorState& m = g_mirrors[mirror_idx];
      m.fail_count++;
      m.ema_speed_bps = std::max(64.0 * 1024.0, m.ema_speed_bps * 0.6);
      const auto target = now + std::chrono::milliseconds(cooldown_ms);
      if (target > m.cooldown_until) m.cooldown_until = target;
      if (expire_direct_url) m.direct_url.clear();
    }
    for (const auto& m : g_mirrors) {
      if (!m.dead && now >= m.cooldown_until) {
        all_throttled = false;
        break;
      }
    }
  }

  if (all_throttled) {
    int cur = g_allowed_workers.load();
    if (cur > 1) {
      const int next = (status_code == 429 || status_code == 503) ? std::max(1, cur / 2) : (cur - 1);
      g_allowed_workers.compare_exchange_strong(cur, next);
    }
  }
}

// Returns false (and leaves the mirror alive) if it is the last alive one and !even_if_last.
bool DisableMirror(size_t mirror_idx, bool even_if_last) {
  std::lock_guard<std::mutex> lk(g_mirror_mutex);
  if (mirror_idx >= g_mirrors.size()) return false;
  if (!even_if_last) {
    bool other_alive = false;
    for (size_t i = 0; i < g_mirrors.size(); ++i) {
      if (i != mirror_idx && !g_mirrors[i].dead) other_alive = true;
    }
    if (!other_alive) return false;
  }
  g_mirrors[mirror_idx].dead = true;
  return true;
}

bool WriteAll(HANDLE h, const void* data, size_t size) {
  DWORD written = 0;
  return size == 0 || (WriteFile(h, data, (DWORD)size, &written, nullptr) && written == size);
}

bool ReadAll(HANDLE h, void* data, size_t size) {
  DWORD got = 0;
  return size == 0 || (ReadFile(h, data, (DWORD)size, &got, nullptr) && got == size);
}

// Snapshot -> flush data -> write tmp -> atomic replace. The snapshot only contains
// committed writes, and the flush makes them durable before the state refers to them.
bool SaveStateFile(const std::wstring& meta_path, const MetaIdentity& id, HANDLE data_file) {
  std::vector<MetaSegment> snapshot;
  {
    std::lock_guard<std::mutex> lk(g_seg_mutex);
    for (const auto& s : g_segments) {
      if (s.current < s.end) snapshot.push_back(MetaSegment{s.current, s.end});
    }
  }
  if (data_file) FlushFileBuffers(data_file);

  const std::wstring tmp_path = meta_path + L".tmp";
  HANDLE h = CreateFileW(tmp_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;

  const MetaHeader hdr{kMetaMagic, id.total_size, (uint32_t)snapshot.size(), (uint32_t)id.origin_url.size(),
                       (uint32_t)id.validator.size()};
  bool ok = WriteAll(h, &hdr, sizeof(hdr)) &&
            WriteAll(h, id.origin_url.data(), id.origin_url.size() * sizeof(wchar_t)) &&
            WriteAll(h, id.validator.data(), id.validator.size() * sizeof(wchar_t)) &&
            WriteAll(h, snapshot.data(), snapshot.size() * sizeof(MetaSegment));
  ok = ok && FlushFileBuffers(h);
  CloseHandle(h);

  if (ok) ok = MoveFileExW(tmp_path.c_str(), meta_path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
  if (!ok) DeleteFileW(tmp_path.c_str());
  return ok;
}

bool LoadStateFile(const std::wstring& meta_path, MetaIdentity& id, std::vector<Segment>& segs) {
  HANDLE h = CreateFileW(meta_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;

  MetaHeader hdr{};
  bool ok = ReadAll(h, &hdr, sizeof(hdr)) && hdr.magic == kMetaMagic && hdr.seg_count > 0 && hdr.seg_count <= 65536 &&
            hdr.url_len <= 32768 && hdr.validator_len <= 4096;
  std::vector<MetaSegment> raw;
  if (ok) {
    id.total_size = hdr.total_size;
    id.origin_url.assign(hdr.url_len, L'\0');
    id.validator.assign(hdr.validator_len, L'\0');
    raw.resize(hdr.seg_count);
    ok = ReadAll(h, id.origin_url.data(), (size_t)hdr.url_len * sizeof(wchar_t)) &&
         ReadAll(h, id.validator.data(), (size_t)hdr.validator_len * sizeof(wchar_t)) &&
         ReadAll(h, raw.data(), raw.size() * sizeof(MetaSegment));
  }
  CloseHandle(h);
  if (!ok) return false;

  segs.clear();
  for (const auto& m : raw) {
    if (m.current < m.end && m.end <= hdr.total_size) segs.push_back(Segment{m.current, m.end, false});
  }
  return !segs.empty();
}

bool AcquireSegment(uint64_t min_split, bool allow_split, size_t& out_index) {
  std::lock_guard<std::mutex> lk(g_seg_mutex);

  for (size_t i = 0; i < g_segments.size(); ++i) {
    Segment& s = g_segments[i];
    if (!s.active && s.current < s.end) {
      s.active = true;
      out_index = i;
      return true;
    }
  }
  if (!allow_split) return false;

  int active = 0;
  uint64_t total_rem = 0, max_rem = 0;
  size_t best = SIZE_MAX;
  for (size_t i = 0; i < g_segments.size(); ++i) {
    const Segment& s = g_segments[i];
    if (s.current >= s.end) continue;
    const uint64_t rem = s.end - s.current;
    total_rem += rem;
    if (!s.active) continue;
    ++active;
    if (rem > max_rem) {
      max_rem = rem;
      best = i;
    }
  }

  const int allowed = g_allowed_workers.load();
  if (best == SIZE_MAX || active >= allowed) return false;

  const bool tail = total_rem < (uint64_t)allowed * min_split;
  const uint64_t floor_size = tail ? kTailMinSplit : min_split;
  if (max_rem < floor_size * 2) return false;

  const uint64_t mid = g_segments[best].current + max_rem / 2;
  const uint64_t old_end = g_segments[best].end;
  g_segments[best].end = mid;
  g_segments.push_back(Segment{mid, old_end, true});
  out_index = g_segments.size() - 1;
  return true;
}

bool AllSegmentsDone() {
  std::lock_guard<std::mutex> lk(g_seg_mutex);
  for (const auto& s : g_segments) {
    if (s.current < s.end) return false;
  }
  return true;
}

uint64_t DoneBytes(bool range_mode, uint64_t total) {
  std::lock_guard<std::mutex> lk(g_seg_mutex);
  if (!range_mode) return g_segments.empty() ? 0 : g_segments[0].current;
  uint64_t rem = 0;
  for (const auto& s : g_segments) {
    if (s.end > s.current) rem += s.end - s.current;
  }
  return total - rem;
}

struct WorkerContext {
  HINTERNET session = nullptr;
  HANDLE shared_file = INVALID_HANDLE_VALUE;
  std::wstring part_path;
  bool range_mode = false;
  bool size_known = false;
  uint64_t total_size = 0;
};

// Reserve -> write -> commit. Returns true when the response ended at a valid point.
bool StreamBody(HINTERNET hReq, HANDLE hFile, size_t seg_idx, bool range_mode, const Config& cfg,
                std::vector<uint8_t>& buf, uint64_t& bytes_out) {
  auto window_start = std::chrono::steady_clock::now();
  uint64_t window_bytes = 0;

  while (!g_stop.load()) {
    DWORD got = 0;
    if (!WinHttpReadData(hReq, buf.data(), (DWORD)buf.size(), &got)) return false;
    if (got == 0) {
      std::lock_guard<std::mutex> lk(g_seg_mutex);
      Segment& s = g_segments[seg_idx];
      if (s.end == kUnknownEnd) s.end = s.current;
      return s.current >= s.end;
    }

    uint64_t offset = 0;
    DWORD to_write = 0;
    {
      std::lock_guard<std::mutex> lk(g_seg_mutex);
      const Segment& s = g_segments[seg_idx];
      offset = s.current;
      if (s.current < s.end) to_write = (DWORD)std::min<uint64_t>(got, s.end - s.current);
    }
    if (to_write == 0) return true;

    OVERLAPPED ov{};
    ov.Offset = (DWORD)(offset & 0xFFFFFFFFULL);
    ov.OffsetHigh = (DWORD)(offset >> 32);
    DWORD written = 0;
    if (!WriteFile(hFile, buf.data(), to_write, &written, &ov) || written != to_write) {
      const DWORD err = GetLastError();
      fprintf(stderr, "\n[!] Disk write error (%lu)\n", err);
      TriggerStop(StopReason::DiskError);
      return false;
    }

    bool seg_full = false;
    {
      std::lock_guard<std::mutex> lk(g_seg_mutex);
      Segment& s = g_segments[seg_idx];
      s.current = offset + written;
      seg_full = s.current >= s.end;
    }
    bytes_out += written;
    if (range_mode) g_fail_streak.store(0);
    if (seg_full) return true;

    if (range_mode && cfg.min_speed_bps > 0) {
      window_bytes += written;
      const auto now = std::chrono::steady_clock::now();
      const double win = std::chrono::duration<double>(now - window_start).count();
      if (win >= cfg.timeout_sec) {
        if ((double)window_bytes < (double)cfg.min_speed_bps * win) return false;
        window_start = now;
        window_bytes = 0;
      }
    }
  }
  return false;
}

void WorkerThread(int worker_id, const WorkerContext& ctx, const Config& cfg) {
  std::vector<uint8_t> buf(kIoBufSize);
  HANDLE own_file = CreateFileW(ctx.part_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  HANDLE hFile = (own_file != INVALID_HANDLE_VALUE) ? own_file : ctx.shared_file;

  HINTERNET hConn = nullptr;
  std::wstring conn_host;
  INTERNET_PORT conn_port = 0;
  auto drop_conn = [&] {
    CloseAndUnregisterHandle(hConn);
    conn_host.clear();
  };

  while (!ShouldQuit()) {
    if (worker_id >= g_allowed_workers.load()) {
      drop_conn();
      if (AllSegmentsDone() || !InterruptibleSleep(500)) break;
      continue;
    }

    size_t seg_idx = 0;
    if (!AcquireSegment(cfg.min_split, ctx.range_mode, seg_idx)) {
      drop_conn();
      if (AllSegmentsDone() || !InterruptibleSleep(200)) break;
      continue;
    }

    g_running_workers.fetch_add(1);
    auto release_seg = [&] {
      std::lock_guard<std::mutex> lk(g_seg_mutex);
      g_segments[seg_idx].active = false;
    };

    while (true) {
      if (g_stop.load() || (worker_id > 0 && worker_id >= g_allowed_workers.load())) {
        release_seg();
        break;
      }

      uint64_t req_start = 0, req_end = 0;
      {
        std::lock_guard<std::mutex> lk(g_seg_mutex);
        Segment& s = g_segments[seg_idx];
        req_start = s.current;
        req_end = s.end;
        if (req_start >= req_end) {
          s.active = false;
          break;
        }
      }

      size_t mirror_idx = 0;
      std::wstring target_url;
      bool is_refresh = false;
      if (!SelectAndPaceMirror(worker_id, mirror_idx, target_url, is_refresh)) {
        release_seg();
        TriggerStop(StopReason::NoMirrors);
        break;
      }

      ParsedUrl pu;
      if (!ParseUrl(target_url, pu)) {
        DisableMirror(mirror_idx, true);
        ReleaseMirrorWorker(mirror_idx, 0, 0.0, true);
        continue;
      }

      const auto attempt_start = std::chrono::steady_clock::now();
      uint64_t bytes_this_attempt = 0;
      bool failed = true;
      bool reset_conn = false;

      if (!hConn || conn_host != pu.host || conn_port != pu.port) {
        drop_conn();
        hConn = WinHttpConnect(ctx.session, pu.host.c_str(), pu.port, 0);
        RegisterHandle(hConn);
        if (hConn) {
          conn_host = pu.host;
          conn_port = pu.port;
        }
      }
      HINTERNET hReq = hConn ? OpenGetRequest(hConn, pu, cfg, is_refresh) : nullptr;

      std::wstring headers;
      if (ctx.range_mode) {
        wchar_t range_hdr[96];
        swprintf(range_hdr, 96, L"Range: bytes=%llu-%llu\r\n", (unsigned long long)req_start,
                 (unsigned long long)(req_end - 1));
        headers = range_hdr;
      }

      if (!hReq || !SendAndReceive(hReq, headers)) {
        PenalizeMirror(mirror_idx, 0, nullptr, false);
        reset_conn = true;
      } else {
        const DWORD status = QueryStatus(hReq);
        bool accept = false;

        if (status == 206 && ctx.range_mode) {
          const ContentRange cr = QueryContentRange(hReq);
          if (!cr.valid || cr.start != req_start) {
            PenalizeMirror(mirror_idx, (int)status, hReq, false);
          } else if (cr.has_total && cr.total != ctx.total_size) {
            fprintf(stderr, "\n[!] Mirror #%zu size mismatch (%llu != %llu). Disabling mirror.\n", mirror_idx + 1,
                    (unsigned long long)cr.total, (unsigned long long)ctx.total_size);
            DisableMirror(mirror_idx, true);
          } else {
            accept = true;
          }
        } else if (status == 200 && !ctx.range_mode) {
          uint64_t len = 0;
          if (ctx.size_known && QueryContentLength(hReq, len) && len != ctx.total_size) {
            fprintf(stderr, "\n[!] Mirror #%zu size mismatch (%llu != %llu). Disabling mirror.\n", mirror_idx + 1,
                    (unsigned long long)len, (unsigned long long)ctx.total_size);
            DisableMirror(mirror_idx, true);
          } else {
            accept = true;
          }
        } else if (status == 200 || status == 206) {
          if (DisableMirror(mirror_idx, false)) {
            fprintf(stderr, "\n[!] Mirror #%zu does not honor Range requests. Disabling mirror.\n", mirror_idx + 1);
          } else {
            PenalizeMirror(mirror_idx, (int)status, hReq, false);
          }
        } else if (status == 401 || status == 403 || status == 410) {
          PenalizeMirror(mirror_idx, (int)status, hReq, true);
          reset_conn = true;
        } else if (status == 404 && !is_refresh) {
          PenalizeMirror(mirror_idx, (int)status, hReq, true);
        } else if (status == 404) {
          if (DisableMirror(mirror_idx, false)) {
            fprintf(stderr, "\n[!] Mirror #%zu returned 404. Disabling mirror.\n", mirror_idx + 1);
          } else {
            PenalizeMirror(mirror_idx, (int)status, hReq, false);
          }
        } else {
          PenalizeMirror(mirror_idx, (int)status, hReq, false);
        }

        if (accept) {
          if (is_refresh) {
            const std::wstring final_url = GetFinalUrlFromRequest(hReq, target_url);
            std::lock_guard<std::mutex> lk(g_mirror_mutex);
            g_mirrors[mirror_idx].direct_url = final_url;
          }
          failed = !StreamBody(hReq, hFile, seg_idx, ctx.range_mode, cfg, buf, bytes_this_attempt);
        }
      }

      CloseAndUnregisterHandle(hReq);
      if (reset_conn) drop_conn();

      if (!ctx.range_mode && failed) {
        std::lock_guard<std::mutex> lk(g_seg_mutex);
        g_segments[seg_idx].current = 0;  // sequential mode cannot resume mid-stream
      }

      const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - attempt_start).count();
      ReleaseMirrorWorker(mirror_idx, bytes_this_attempt, elapsed, failed);

      bool seg_done = false;
      {
        std::lock_guard<std::mutex> lk(g_seg_mutex);
        Segment& s = g_segments[seg_idx];
        seg_done = s.current >= s.end;
        if (seg_done) s.active = false;
      }
      if (seg_done) {
        g_fail_streak.store(0);
        break;
      }
      if (g_stop.load()) {
        release_seg();
        break;
      }

      g_total_retries.fetch_add(1);
      int backoff_ms = 300;
      if (bytes_this_attempt == 0 || !ctx.range_mode) {
        const int streak = g_fail_streak.fetch_add(1) + 1;
        if (cfg.max_giveup_streak > 0 && streak >= cfg.max_giveup_streak) {
          release_seg();
          TriggerStop(StopReason::GiveUp);
          break;
        }
        const int n = (int)g_mirrors.size();
        backoff_ms = (n > 1 && streak < n * 2) ? 200 : std::min(500 * streak, 5000);
      }
      if (!InterruptibleSleep(backoff_ms)) {
        release_seg();
        break;
      }
    }

    g_running_workers.fetch_sub(1);
  }

  drop_conn();
  if (own_file != INVALID_HANDLE_VALUE) CloseHandle(own_file);
}

bool ComputeFileSha256(HANDLE hFile, std::wstring& out_hex) {
  LARGE_INTEGER zero{};
  if (!SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN)) return false;

  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCRYPT_HASH_HANDLE hHash = nullptr;
  bool ok = false;

  if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
    if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
      std::vector<uint8_t> buf(4 * 1024 * 1024);
      DWORD read_bytes = 0;
      bool read_ok = true;
      while (!g_stop.load()) {
        if (!ReadFile(hFile, buf.data(), (DWORD)buf.size(), &read_bytes, nullptr)) {
          read_ok = false;
          break;
        }
        if (read_bytes == 0) break;
        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buf.data(), read_bytes, 0))) {
          read_ok = false;
          break;
        }
      }
      uint8_t digest[32] = {};
      if (read_ok && !g_stop.load() && BCRYPT_SUCCESS(BCryptFinishHash(hHash, digest, sizeof(digest), 0))) {
        wchar_t hex_buf[65] = {};
        for (int i = 0; i < 32; ++i) swprintf(hex_buf + i * 2, 3, L"%02x", digest[i]);
        out_hex.assign(hex_buf, 64);
        ok = true;
      }
      BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
  }
  return ok;
}

std::wstring NormalizeSha256Arg(std::wstring raw) {
  raw = ToLower(raw);
  if (raw.rfind(L"sha256:", 0) == 0) raw = raw.substr(7);
  if (raw == L"auto") return L"";
  if (raw == L"-" || raw == L"show" || raw == L"print") return L"print";
  return raw;
}

bool CheckExistingFileMatches(const std::wstring& path, bool size_known, uint64_t expected_size,
                              const std::wstring& expected_sha256) {
  HANDLE hExisting = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hExisting == INVALID_HANDLE_VALUE) return false;

  LARGE_INTEGER sz{};
  if (!GetFileSizeEx(hExisting, &sz) || (size_known && (uint64_t)sz.QuadPart != expected_size)) {
    CloseHandle(hExisting);
    return false;
  }

  std::wstring actual_hex;
  const bool ok = ComputeFileSha256(hExisting, actual_hex);
  CloseHandle(hExisting);
  return ok && actual_hex == expected_sha256;
}

void PrintUsage() {
  printf(
      "uget v4.1 - Immortal Multi-Mirror CLI Downloader (UCRT + WinHTTP + CNG)\n"
      "Usage: uget [options] <URL1> [URL2 ...]\n\n"
      "Options:\n"
      "  -o, -O <file>        Output filename (default: auto-detect)\n"
      "  -x <connections>     Max concurrent connections (default: 8, max: 64)\n"
      "  -t <streak>          Give up after N consecutive failed attempts (default: 25, 0=infinite)\n"
      "  --timeout <sec>      Socket timeout and low-speed window in seconds (default: 15)\n"
      "  --min-speed <KiB/s>  Drop a ranged connection slower than this over the window (default: 1, 0=off)\n"
      "  --sha256 <hash>      Verify against this SHA-256 ('print' to show the digest)\n"
      "  --no-sha-sidecar     Do not look for a published checksum next to the URL\n"
      "  --http2              Allow HTTP/2 (connections to the same host get multiplexed)\n"
      "  -q, --quiet          Quiet mode (suppress progress bar & info logs)\n"
      "  -k                   Allow insecure TLS and HTTPS->HTTP redirects\n"
      "\n"
      "Without a --sha256 hash, <URL>.sha256, <URL>.sha256sum, SHA256SUMS or sha256sums.txt\n"
      "next to the file is used for verification when one can be found.\n");
}

int main() {
  setlocale(LC_CTYPE, ".UTF8");
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (!argv || argc < 2) {
    PrintUsage();
    if (argv) LocalFree(argv);
    return 1;
  }

  Config cfg;
  DWORD console_mode = 0;
  cfg.is_tty = (GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &console_mode) != 0);

  for (int i = 1; i < argc; ++i) {
    const std::wstring arg = argv[i];
    const bool has_value = i + 1 < argc;
    if ((arg == L"-o" || arg == L"-O") && has_value) {
      cfg.output = argv[++i];
    } else if (arg == L"-x" && has_value) {
      cfg.threads = std::clamp(_wtoi(argv[++i]), 1, 64);
    } else if (arg == L"-t" && has_value) {
      cfg.max_giveup_streak = std::max(0, _wtoi(argv[++i]));
    } else if (arg == L"--timeout" && has_value) {
      cfg.timeout_sec = std::max(3, _wtoi(argv[++i]));
    } else if (arg == L"--min-speed" && has_value) {
      cfg.min_speed_bps = (uint64_t)std::max(0, _wtoi(argv[++i])) * 1024;
    } else if (arg == L"--sha256" && has_value) {
      cfg.expected_sha256 = NormalizeSha256Arg(argv[++i]);
    } else if (arg == L"--no-sha-sidecar") {
      cfg.sha_sidecar = false;
    } else if (arg == L"--http2") {
      cfg.http2 = true;
    } else if (arg == L"-q" || arg == L"--quiet") {
      cfg.quiet = true;
    } else if (arg == L"-k" || arg == L"--no-check-certificate") {
      cfg.insecure = true;
    } else if (arg == L"-h" || arg == L"--help") {
      PrintUsage();
      LocalFree(argv);
      return 0;
    } else if (!arg.empty() && arg[0] == L'-') {
      fwprintf(stderr, L"[!] Unknown or incomplete option: %ls\n", arg.c_str());
      LocalFree(argv);
      return 1;
    } else if (!arg.empty()) {
      cfg.urls.push_back(arg);
    }
  }
  LocalFree(argv);

  if (cfg.urls.empty()) {
    PrintUsage();
    return 1;
  }
  const bool print_sha = cfg.expected_sha256 == L"print";
  std::wstring expected_sha = print_sha ? L"" : cfg.expected_sha256;
  if (!expected_sha.empty() && !IsSha256Hex(expected_sha)) {
    fprintf(stderr, "[!] --sha256 expects 64 hex characters or 'print'.\n");
    return 1;
  }

  g_quiet = cfg.quiet;
  g_allowed_workers.store(cfg.threads);

  for (const auto& u : cfg.urls) {
    MirrorState ms{};
    ms.original_url = u;
    g_mirrors.push_back(std::move(ms));
  }

  HINTERNET hSession = WinHttpOpen(
      L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    fprintf(stderr, "[!] WinHttpOpen failed (%lu)\n", GetLastError());
    return 1;
  }

  const int t_ms = cfg.timeout_sec * 1000;
  WinHttpSetTimeouts(hSession, t_ms, t_ms, t_ms, t_ms);

  DWORD redirect_policy =
      cfg.insecure ? WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS : WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
  WinHttpSetOption(hSession, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));

  DWORD max_conns = (DWORD)std::max(cfg.threads * 2, 32);
  WinHttpSetOption(hSession, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &max_conns, sizeof(max_conns));
  WinHttpSetOption(hSession, WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER, &max_conns, sizeof(max_conns));

  LogInfo("[*] Probing %zu mirror(s)...\n", g_mirrors.size());
  const ProbeResult probe = ProbeMirrors(hSession, cfg);
  if (!probe.ok) {
    WinHttpCloseHandle(hSession);
    if (g_user_abort.load()) {
      fprintf(stderr, "\n[!] Cancelled by Ctrl+C.\n");
      return 130;
    }
    fprintf(stderr, "[!] Failed to probe target URL(s).\n");
    return 1;
  }

  const bool range_mode = probe.supports_range;
  const std::wstring out_file = cfg.output.empty() ? probe.filename : cfg.output;
  const std::wstring part_file = out_file + L".part";
  const std::wstring meta_file = out_file + L".uget";
  const std::wstring meta_tmp_file = meta_file + L".tmp";

  std::wstring sha_source;
  if (expected_sha.empty() && cfg.sha_sidecar) {
    expected_sha = FindSidecarSha256(hSession, cfg, probe, sha_source);
    if (g_stop.load()) {
      WinHttpCloseHandle(hSession);
      fprintf(stderr, "\n[!] Cancelled by Ctrl+C.\n");
      return 130;
    }
    if (!expected_sha.empty()) {
      LogInfoW(L"[*] SHA-256 from %ls\n", sha_source.c_str());
    } else {
      LogInfo("[*] No published checksum found. Integrity will not be verified.\n");
    }
  }

  if (!expected_sha.empty() && CheckExistingFileMatches(out_file, probe.size_known, probe.total_size, expected_sha)) {
    LogInfoW(L"[+] '%ls' already exists and SHA-256 matches. Skipping download.\n", out_file.c_str());
    WinHttpCloseHandle(hSession);
    return 0;
  }

  wchar_t size_buf[48] = L"unknown";
  if (probe.size_known) swprintf(size_buf, 48, L"%.2f MiB", probe.total_size / kMiB);
  const int launch_count = range_mode ? cfg.threads : 1;
  LogInfoW(L"[*] File: %ls | Size: %ls | Mirrors: %zu | Mode: %ls | Max-Conns: %d\n", out_file.c_str(), size_buf,
           g_mirrors.size(), range_mode ? L"ranged" : L"sequential", launch_count);

  MetaIdentity ident{probe.total_size, probe.origin_url, probe.validator};
  bool resumed = false;
  if (range_mode && GetFileAttributesW(part_file.c_str()) != INVALID_FILE_ATTRIBUTES) {
    MetaIdentity saved;
    std::vector<Segment> segs;
    if (LoadStateFile(meta_file, saved, segs) && saved.total_size == probe.total_size) {
      const bool comparable = saved.origin_url == ident.origin_url && saved.validator.size() > 3 &&
                              ident.validator.size() > 3 && saved.validator.compare(0, 3, ident.validator, 0, 3) == 0;
      if (comparable && saved.validator != ident.validator) {
        LogInfo("[*] Remote file changed since the last run. Starting over.\n");
      } else {
        if (saved.origin_url != ident.origin_url) ident = saved;
        g_segments = std::move(segs);
        resumed = true;
        LogInfo("[*] Resuming from saved .uget state...\n");
      }
    }
  }
  if (!range_mode) DeleteFileW(meta_file.c_str());

  HANDLE hFile = CreateFileW(part_file.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             resumed ? OPEN_EXISTING : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "[!] Failed to open .part file (%lu)\n", GetLastError());
    WinHttpCloseHandle(hSession);
    return 1;
  }

  if (!resumed) {
    if (range_mode) {
      // Sparse avoids NTFS zero-filling up to the valid data length on out-of-order writes.
      DWORD ret = 0;
      DeviceIoControl(hFile, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &ret, nullptr);
    }
    if (probe.size_known && probe.total_size > 0) {
      LARGE_INTEGER li{};
      li.QuadPart = (LONGLONG)probe.total_size;
      if (!SetFilePointerEx(hFile, li, nullptr, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        fprintf(stderr, "[!] Failed to allocate .part file (%lu)\n", GetLastError());
        CloseHandle(hFile);
        WinHttpCloseHandle(hSession);
        return 1;
      }
    }

    if (range_mode) {
      const uint64_t total = probe.total_size;
      int n = cfg.threads;
      if (total < (uint64_t)cfg.threads * cfg.min_split) n = (int)std::max<uint64_t>(1, total / cfg.min_split);
      const uint64_t chunk = total / n;
      for (int i = 0; i < n; ++i) {
        const uint64_t s = (uint64_t)i * chunk;
        const uint64_t e = (i == n - 1) ? total : (uint64_t)(i + 1) * chunk;
        g_segments.push_back(Segment{s, e, false});
      }
      SaveStateFile(meta_file, ident, nullptr);
    } else {
      g_segments.push_back(Segment{0, probe.size_known ? probe.total_size : kUnknownEnd, false});
    }
  }

  WorkerContext ctx;
  ctx.session = hSession;
  ctx.shared_file = hFile;
  ctx.part_path = part_file;
  ctx.range_mode = range_mode;
  ctx.size_known = probe.size_known;
  ctx.total_size = probe.total_size;

  g_allowed_workers.store(launch_count);
  std::vector<std::thread> workers;
  for (int i = 0; i < launch_count; ++i) {
    workers.emplace_back(WorkerThread, i, std::cref(ctx), std::cref(cfg));
  }

  auto last_time = std::chrono::steady_clock::now();
  uint64_t last_bytes = DoneBytes(range_mode, probe.total_size);
  int tick = 0;
  int stable_ticks = 0;
  uint64_t last_retries = 0;
  int64_t last_milestone = -1;

  while (!g_stop.load() && !AllSegmentsDone()) {
    if (!InterruptibleSleep(500)) break;
    if (range_mode && ++tick % kMetaSaveTicks == 0) SaveStateFile(meta_file, ident, hFile);

    const uint64_t done_bytes = DoneBytes(range_mode, probe.total_size);
    const auto now = std::chrono::steady_clock::now();
    const double dt = std::chrono::duration<double>(now - last_time).count();
    const double speed_mib = (dt > 0.0 && done_bytes >= last_bytes) ? (done_bytes - last_bytes) / dt / kMiB : 0.0;
    last_time = now;
    last_bytes = done_bytes;

    const uint64_t retries = g_total_retries.load();
    if (retries == last_retries && speed_mib > 0.1) {
      if (++stable_ticks >= 20) {
        stable_ticks = 0;
        int cur = g_allowed_workers.load();
        if (cur < launch_count) g_allowed_workers.compare_exchange_strong(cur, cur + 1);
      }
    } else {
      stable_ticks = 0;
      last_retries = retries;
    }

    if (cfg.quiet) continue;
    const double done_mib = done_bytes / kMiB;
    if (cfg.is_tty) {
      if (probe.size_known) {
        const double pct = probe.total_size > 0 ? 100.0 * done_bytes / probe.total_size : 100.0;
        printf("\r[%5.1f%%] %.2f/%.2f MiB | %6.2f MiB/s | Conns: %d/%d | Retries: %llu (Streak: %d/%d)   ", pct,
               done_mib, probe.total_size / kMiB, speed_mib, g_running_workers.load(), g_allowed_workers.load(),
               (unsigned long long)retries, g_fail_streak.load(), cfg.max_giveup_streak);
      } else {
        printf("\r[  ?.?%%] %.2f MiB | %6.2f MiB/s | Retries: %llu (Streak: %d/%d)   ", done_mib, speed_mib,
               (unsigned long long)retries, g_fail_streak.load(), cfg.max_giveup_streak);
      }
      fflush(stdout);
    } else {
      const int64_t milestone = (probe.size_known && probe.total_size > 0)
                                    ? (int64_t)(done_bytes * 4 / probe.total_size)
                                    : (int64_t)(done_bytes / (256ULL << 20));
      if (milestone > last_milestone) {
        last_milestone = milestone;
        if (!probe.size_known) {
          printf("[*] Progress: %.2f MiB (%.2f MiB/s)\n", done_mib, speed_mib);
        } else if (milestone < 4) {
          printf("[*] Progress: %d%% (%.2f / %.2f MiB, %.2f MiB/s)\n", (int)milestone * 25, done_mib,
                 probe.total_size / kMiB, speed_mib);
        }
        fflush(stdout);
      }
    }
  }

  const bool completed = AllSegmentsDone();
  if (completed) {
    MarkDone();
  } else {
    AbortAllActiveHandles();
  }
  for (auto& th : workers) {
    if (th.joinable()) th.join();
  }
  WinHttpCloseHandle(hSession);

  if (completed) {
    const uint64_t final_size = range_mode ? probe.total_size : g_segments[0].end;
    if (range_mode) {
      BOOLEAN sparse_off = FALSE;
      DWORD ret = 0;
      DeviceIoControl(hFile, FSCTL_SET_SPARSE, &sparse_off, sizeof(sparse_off), nullptr, 0, &ret, nullptr);
    }
    if (!probe.size_known) {
      LARGE_INTEGER li{};
      li.QuadPart = (LONGLONG)final_size;
      SetFilePointerEx(hFile, li, nullptr, FILE_BEGIN);
      SetEndOfFile(hFile);
    }
    FlushFileBuffers(hFile);

    if (!cfg.quiet && cfg.is_tty) {
      printf("\r[100.0%%] %.2f MiB | Download Complete! (Retries: %llu)                                        \n",
             final_size / kMiB, (unsigned long long)g_total_retries.load());
    }

    if (print_sha || !expected_sha.empty()) {
      LogInfo("[*] Calculating SHA-256...\n");
      std::wstring actual_sha256;
      if (!ComputeFileSha256(hFile, actual_sha256)) {
        CloseHandle(hFile);
        fprintf(stderr, "[!] Failed to compute SHA-256 (or interrupted).\n");
        return g_user_abort.load() ? 130 : 1;
      }
      if (print_sha) wprintf(L"%ls  %ls\n", actual_sha256.c_str(), out_file.c_str());
      if (!expected_sha.empty() && actual_sha256 != expected_sha) {
        CloseHandle(hFile);
        fwprintf(stderr,
                 L"[!] SHA-256 MISMATCH for '%ls'!\n"
                 L"    Expected: %ls\n"
                 L"    Actual  : %ls\n",
                 out_file.c_str(), expected_sha.c_str(), actual_sha256.c_str());
        DeleteFileW(meta_file.c_str());
        DeleteFileW(meta_tmp_file.c_str());
        if (sha_source.empty()) {
          DeleteFileW(part_file.c_str());
        } else {
          // A stale published checksum must not trigger an endless re-download loop.
          fwprintf(stderr, L"    Source  : %ls\n    Kept '%ls' for inspection.\n", sha_source.c_str(), part_file.c_str());
        }
        return 2;
      }
      if (!expected_sha.empty()) LogInfoW(L"[+] SHA-256 verified OK (%ls)\n", actual_sha256.c_str());
    }

    CloseHandle(hFile);
    if (!MoveFileExW(part_file.c_str(), out_file.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      const DWORD err = GetLastError();
      fwprintf(stderr, L"[!] Failed to rename '%ls' -> '%ls' (%lu)\n", part_file.c_str(), out_file.c_str(), err);
      return 1;
    }
    DeleteFileW(meta_file.c_str());
    DeleteFileW(meta_tmp_file.c_str());
    if (!cfg.is_tty) LogInfoW(L"[+] Saved '%ls' (%.2f MiB)\n", out_file.c_str(), final_size / kMiB);
    return 0;
  }

  if (range_mode) SaveStateFile(meta_file, ident, hFile);
  CloseHandle(hFile);

  const char* saved_note = range_mode ? " Progress saved." : "";
  switch ((StopReason)g_stop_reason.load()) {
    case StopReason::User:
      fprintf(stderr, "\n[!] Cancelled by Ctrl+C.%s\n", saved_note);
      return 130;
    case StopReason::NoMirrors:
      fprintf(stderr, "\n[!] Aborted: no usable mirror left.%s\n", saved_note);
      return 1;
    case StopReason::DiskError:
      fprintf(stderr, "\n[!] Aborted: disk write error.%s\n", saved_note);
      return 1;
    default:
      fprintf(stderr, "\n[!] Aborted: %d consecutive attempts failed.%s\n", cfg.max_giveup_streak, saved_note);
      return 1;
  }
}