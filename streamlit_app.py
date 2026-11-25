#!/usr/bin/env python3
"""waf3 — أداة فحص بيانات تيك توك العامة (ملف واحد: واجهة ويب Streamlit عصرية + سطر أوامر CLI).
Install: pip install streamlit requests curl_cffi yt-dlp
Web UI:        streamlit run waf3.py
CLI Audit:     python waf3.py --worker USERNAME
CLI Usernames: python waf3.py --check-usernames user1 user2
CLI Video:     python waf3.py --video https://www.tiktok.com/@user/video/7400000000000000000
CLI Compare:   python waf3.py --compare userA userB
لا تكشف البيانات عنوان IP أو الموقع الفعلي أو استخدام VPN. لا نستخدم نتائج مختلقة.
"""
from __future__ import annotations

import csv
import hmac
import io
import json
import os
import random
import re
import statistics as st
import sys
import time
from datetime import datetime, timezone

try:
    from curl_cffi import requests as http
    IMPERSONATE = True
except ImportError:
    try:
        import requests as http
    except ImportError:
        http = None
    IMPERSONATE = False

HYDRATION_RE = re.compile(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', re.S)
STATUS = {
    0: "ok",
    10221: "not_found_or_banned",
    10222: "private",
    10223: "restricted",
    10202: "not_found",
    10204: "video_unavailable",
}
BUCKET_ZONE = {
    "useast5": "NA",
    "useast8": "NA",
    "no1a": "EU",
    "useast2a": "EU",
    "alisg": "ROW",
    "maliva": "LEGACY",
}
EU_ZONE = set(
    "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE IS LI NO GB CH".split()
)
LIMITATIONS_AR = [
    "لا تكشف البيانات عنوان IP أو موقع الشخص أو استخدام VPN.",
    "مصادر القيم هي جامع البيانات الأصلي؛ توقيت الجمع ليس ضماناً لحداثة كل عداد.",
    "لا يتوفر سجل دائم، وقد تتعطل واجهات تيك توك غير الموثقة.",
    "نتائج Shadowban و 200–300 View Jail و FYP و Trust Score مبنية على مؤشرات عامة مرصودة وليست قراءة لنظام تيك توك الداخلي.",
]


class FetchError(Exception):
    pass


class Fetcher:
    def __init__(self, delay: float = 1.0, retries: int = 3, timeout: int = 22, proxy: str | None = None):
        self.delay = delay
        self.retries = retries
        self.timeout = timeout
        self.proxy = proxy
        self.log: list[str] = []
        self._last = 0.0
        self._new()

    def _new(self) -> None:
        if http is None:
            raise FetchError("Missing HTTP library. Run: pip install requests curl_cffi")
        self.s = http.Session(impersonate="chrome") if IMPERSONATE else http.Session()
        if not IMPERSONATE:
            self.s.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            )
        self.s.headers["Accept-Language"] = "en-US,en;q=0.9,ar;q=0.8"
        if self.proxy:
            self.s.proxies = {"http": self.proxy, "https": self.proxy}

    def _wait(self) -> None:
        gap = self.delay + random.uniform(0, self.delay * 0.4)
        dt = time.time() - self._last
        if dt < gap:
            time.sleep(gap - dt)
        self._last = time.time()

    def _get(self, url: str, parse, **kw):
        err = None
        for a in range(self.retries):
            self._wait()
            try:
                r = self.s.get(url, timeout=self.timeout, **kw)
            except Exception as exc:
                err = f"network: {exc}"
            else:
                if r.status_code in (429, 503) or r.status_code >= 500:
                    err = f"http {r.status_code} (rate limit/server)"
                elif r.status_code == 403:
                    err = "http 403 (blocked)"
                    if a >= 1:
                        self.log.append(f"{url[:90]} try {a + 1}: {err}; giving up")
                        break
                else:
                    try:
                        out = parse(r.text)
                        if out is not None:
                            return out
                        err = "empty/unsigned response"
                    except ValueError as exc:
                        err = f"parse: {exc}"
            wait = (2 ** a) * 1.5 + random.uniform(0, 1.0)
            self.log.append(f"{url[:90]} try {a + 1}: {err}; sleep {wait:.1f}s")
            if a >= 1:
                self._new()
            time.sleep(wait)
        raise FetchError(f"{url}: {err}")

    def hydration(self, url: str) -> dict:
        def parse(t: str) -> dict:
            m = HYDRATION_RE.search(t)
            if not m:
                if "captcha" in t.lower() or "verify" in t.lower()[:5000]:
                    raise ValueError("captcha / bot wall")
                raise ValueError("hydration script missing")
            return json.loads(m.group(1)).get("__DEFAULT_SCOPE__", {})

        return self._get(url, parse)

    def api(self, url: str, referer: str = "https://www.tiktok.com/") -> dict:
        return self._get(
            url,
            lambda t: json.loads(t) if t.strip() else None,
            headers={"Referer": referer},
        )


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def id_to_unix(i):
    i = _int(i)
    if not i or i < 2 ** 40:
        return None
    t = i >> 32
    return t if 1_400_000_000 < t < 2_100_000_000 else None


def iso(t):
    return datetime.fromtimestamp(int(t), timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else None


def bucket(url: str | None) -> str | None:
    m = re.search(r"/tos-([a-z0-9]+)-(?:avt|p|i)-", url or "")
    return m.group(1) if m else None


def _med(x):
    x = [v for v in x if v is not None]
    return st.median(x) if x else None


def _pct(x):
    return None if x is None else round(100 * x, 3)


def _close(a, b, rel=0.02, abs_=5):
    return a is not None and b is not None and abs(a - b) <= max(abs_, rel * max(abs(a), abs(b)))


def get_profile(f: Fetcher, username: str) -> dict:
    username = username.lstrip("@").strip()
    ud = f.hydration(f"https://www.tiktok.com/@{username}").get("webapp.user-detail")
    if ud is None:
        raise FetchError("user-detail block missing")
    code = ud.get("statusCode")
    ui = ud.get("userInfo") or {}
    u, exact, rnd = ui.get("user") or {}, ui.get("statsV2") or {}, ui.get("stats") or {}
    stats = {
        k: _int(exact.get(k, rnd.get(k)))
        for k in ("followerCount", "followingCount", "heartCount", "videoCount", "friendCount", "diggCount")
    }
    cu = u.get("commerceUserInfo") or {}
    bio_link = (u.get("bioLink") or {}).get("link")
    return {
        "status_code": code,
        "status": STATUS.get(code, f"unknown_{code}"),
        "status_msg": ud.get("statusMsg"),
        "exact_stats": bool(exact),
        "id": u.get("id"),
        "secUid": u.get("secUid"),
        "uniqueId": u.get("uniqueId") or username,
        "nickname": u.get("nickname"),
        "signature": u.get("signature"),
        "bio_link": bio_link,
        "verified": u.get("verified"),
        "private": u.get("privateAccount"),
        "language": u.get("language"),
        "createTime": _int(u.get("createTime")) or None,
        "id_time": id_to_unix(u.get("id")),
        "uniqueIdModifyTime": _int(u.get("uniqueIdModifyTime")) or None,
        "nickNameModifyTime": _int(u.get("nickNameModifyTime")) or None,
        "commerce": cu.get("commerceUser"),
        "isOrganization": u.get("isOrganization"),
        "embed_banned": u.get("isEmbedBanned"),
        "tt_seller": u.get("ttSeller"),
        "room_id": u.get("roomId") or None,
        "download_setting": _int(u.get("downloadSetting")),
        "open_favorite": u.get("openFavorite"),
        "following_visibility": _int(u.get("followingVisibility")),
        "avatar_bucket": bucket(u.get("avatarThumb")),
        "stats": stats,
        "fetched_at": int(time.time()),
    }


def list_videos_embed(f: Fetcher, username: str, limit: int = 12) -> list[dict]:
    clean = username.lstrip("@")
    html = f._get(f"https://www.tiktok.com/embed/@{clean}", lambda t: t if t.strip() else None)
    m = re.search(r'<script[^>]*id="__FRONTITY_CONNECT_STATE__"[^>]*>([\s\S]*?)</script>', html) or re.search(
        r'<script[^>]*>(\{"service":[\s\S]*?)</script>', html
    )
    out: list[dict] = []
    if m:
        try:
            ej = json.loads(m.group(1))
            data_map = (ej.get("source") or {}).get("data") or {}
            block = data_map.get(f"/embed/@{clean}") or data_map.get(f"/embed/@{clean.lower()}")
            if not isinstance(block, dict):
                block = next((v for v in data_map.values() if isinstance(v, dict) and isinstance(v.get("videoList"), list)), {})
            for v in (block.get("videoList") or [])[:limit]:
                if isinstance(v, dict) and v.get("id"):
                    vid_id = str(v["id"])
                    out.append(
                        {
                            "id": vid_id,
                            "createTime": _int(v.get("createTime")) or id_to_unix(vid_id),
                            "views": _int(v.get("playCount")),
                            "likes": None,
                            "comments": None,
                            "shares": None,
                            "saves": None,
                            "duration": _int(v.get("duration")),
                            "desc": (v.get("desc") or "")[:200],
                            "storage_bucket": bucket(v.get("coverUrl") or v.get("originCoverUrl") or v.get("dynamicCoverUrl")),
                        }
                    )
        except ValueError:
            pass
    if not out:
        for vid_id in list(dict.fromkeys(re.findall(r"\b7\d{18}\b", html)))[:limit]:
            out.append(
                {
                    "id": vid_id,
                    "createTime": id_to_unix(vid_id),
                    "views": None,
                    "likes": None,
                    "comments": None,
                    "shares": None,
                    "saves": None,
                    "duration": None,
                    "desc": "",
                    "storage_bucket": None,
                }
            )
    return out


def list_videos(username: str, limit: int = 12, f: Fetcher | None = None) -> list[dict]:
    if f is not None:
        try:
            embedded = list_videos_embed(f, username, limit)
            if embedded:
                return embedded
        except Exception:
            pass

    try:
        import yt_dlp
    except ImportError:
        raise FetchError("yt-dlp not installed (pip install yt-dlp)")

    class _Quiet:
        def debug(self, m): pass
        def info(self, m): pass
        def warning(self, m): pass
        def error(self, m): pass

    opts = {
        "quiet": True,
        "no_warnings": True,
        "logger": _Quiet(),
        "extract_flat": True,
        "playlistend": limit,
        "skip_download": True,
        "retries": 2,
        "extractor_retries": 2,
        "sleep_interval_requests": 1,
    }
    with yt_dlp.YoutubeDL(opts) as y:
        info = y.extract_info(f"https://www.tiktok.com/@{username.lstrip('@')}", download=False)
    out = []
    for e in (info or {}).get("entries") or []:
        if e and e.get("id"):
            out.append(
                {
                    "id": str(e["id"]),
                    "createTime": _int(e.get("timestamp")) or id_to_unix(e["id"]),
                    "views": _int(e.get("view_count")),
                    "likes": _int(e.get("like_count")),
                    "comments": _int(e.get("comment_count")),
                    "shares": _int(e.get("repost_count")),
                    "saves": _int(e.get("save_count")),
                    "duration": _int(e.get("duration")),
                    "desc": (e.get("description") or "")[:200],
                }
            )
    return out


def get_video(f: Fetcher, username: str, vid: str) -> dict:
    target = f"https://www.tiktok.com/@{username.lstrip('@')}/video/{vid}" if username else f"https://www.tiktok.com/@tiktok/video/{vid}"
    vd = f.hydration(target).get("webapp.video-detail") or {}
    it = (vd.get("itemInfo") or {}).get("itemStruct") or {}
    if not it:
        return {"id": vid, "opened": False, "error": vd.get("statusMsg") or "no item"}
    s = it.get("statsV2") or it.get("stats") or {}
    v, pc = it.get("video") or {}, it.get("penaltyContext") or {}
    music = it.get("music") or {}
    return {
        "id": vid,
        "opened": True,
        "createTime": _int(it.get("createTime")),
        "postedUtc": iso(_int(it.get("createTime"))),
        "locationCreated": it.get("locationCreated"),
        "textLanguage": it.get("textLanguage"),
        "isAd": it.get("isAd"),
        "isAigc": it.get("IsAigc"),
        "suggestedWords": (it.get("suggestedWords") or [])[:6],
        "storage_bucket": bucket(v.get("cover") or v.get("originCover")),
        "moderation": {
            "isProhibited": bool(it.get("isProhibited")),
            "takeDown": _int(it.get("takeDown")) or 0,
            "isReviewing": bool(it.get("isReviewing")),
            "displayPenaltyType": _int(pc.get("display_penalty_type")) or 0,
        },
        "sound": {
            "id": str(music.get("id")) if music.get("id") else None,
            "title": music.get("title"),
            "authorName": music.get("authorName"),
            "original": music.get("original"),
            "copyrighted": music.get("isCopyrighted"),
        },
        "scheduled": bool(_int(it.get("scheduleTime"))),
        "views": _int(s.get("playCount")),
        "likes": _int(s.get("diggCount")),
        "comments": _int(s.get("commentCount")),
        "shares": _int(s.get("shareCount")),
        "saves": _int(s.get("collectCount")),
    }


def get_player_item(f: Fetcher, vid: str) -> dict:
    j = f.api(
        f"https://www.tiktok.com/player/api/v1/items?item_ids={vid}&aid=1284",
        referer=f"https://www.tiktok.com/player/v1/{vid}",
    )
    it = (j.get("items") or [{}])[0]
    res = (j.get("results") or [{}])[0] if not j.get("items") else {}
    st_info = it.get("statistics_info") or {}
    m_info = it.get("music_info") or {}
    v_info = it.get("video_info") or {}
    covers = ((v_info.get("cover") or {}).get("url_list") or []) + ((v_info.get("origin_cover") or {}).get("url_list") or [])
    return {
        "region": it.get("region"),
        "location_created": it.get("location_created"),
        "desc": (it.get("desc") or "")[:200],
        "likes": _int(st_info.get("digg_count")),
        "comments": _int(st_info.get("comment_count")),
        "shares": _int(st_info.get("share_count")),
        "storage_bucket": bucket(covers[0]) if covers else None,
        "sound": (
            {
                "id": str(m_info.get("id_str") or m_info.get("id")) if (m_info.get("id_str") or m_info.get("id")) else None,
                "title": m_info.get("title"),
                "authorName": m_info.get("author"),
                "original": None,
                "copyrighted": None,
            }
            if (m_info.get("title") or m_info.get("id_str"))
            else None
        ),
        "result_code": res.get("code"),
    }


def get_webcast_user(f: Fetcher, uid: str) -> dict:
    j = f.api(f"https://webcast.tiktok.com/webcast/user/?aid=1988&target_uid={uid}")
    d = j.get("data") or {}
    fi = d.get("follow_info") or {}
    return {"followers": _int(fi.get("follower_count")), "following": _int(fi.get("following_count"))}


def check_usernames(usernames: list[str]) -> list[dict]:
    f = Fetcher(delay=0.8, retries=2)
    out = []
    for raw in usernames[:8]:
        handle = raw.strip().lstrip("@").lower()
        if not re.fullmatch(r"[A-Za-z0-9_.]{2,24}", handle) or handle.endswith("."):
            out.append({"username": handle, "validFormat": False, "availability": "invalid"})
            continue
        try:
            p = get_profile(f, handle)
            code = p.get("status_code")
            avail = (
                "available_or_not_found"
                if code == 10202
                else "banned_or_restricted"
                if code in (10221, 10223)
                else "private"
                if p.get("private")
                else "taken_active"
            )
            out.append(
                {
                    "username": p.get("uniqueId") or handle,
                    "validFormat": True,
                    "availability": avail,
                    "statusCode": code,
                    "followers": p["stats"].get("followerCount"),
                    "verified": p.get("verified"),
                    "accountCreated": iso(p.get("createTime")),
                }
            )
        except FetchError as exc:
            out.append({"username": handle, "validFormat": True, "availability": "blocked_by_wall", "error": str(exc)})
    return out


def inspect_video(video_input: str) -> dict:
    m = re.search(r"(\d{15,22})", video_input)
    if not m:
        raise ValueError("معرف الفيديو غير صالح")
    vid = m.group(1)
    um = re.search(r"@([A-Za-z0-9_.]{1,24})", video_input)
    user = um.group(1) if um else ""
    f = Fetcher(delay=0.8, retries=2)
    det = get_video(f, user, vid)
    try:
        pl = get_player_item(f, vid)
    except FetchError:
        pl = {}
    det["accountRegion"] = pl.get("region")
    det["playerLocation"] = pl.get("location_created")
    views = det.get("views") or 0
    det["in_200_300_view_jail_range"] = bool(views and views <= 350)
    return det


def audit(user: str) -> dict:
    user = user.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.]{1,24}", user):
        raise ValueError("اسم المستخدم غير صالح")

    f = Fetcher(delay=1.2, retries=3)
    errors: list[str] = []
    p = get_profile(f, user)
    vids, details = [], {}

    if p["status"] == "ok" and not p["private"]:
        try:
            vids = list_videos(p["uniqueId"], 12, f=f)
        except Exception as exc:
            errors.append(f"video list: {exc}")

        for v in vids[:6]:
            d = {"id": v["id"], "opened": False}
            try:
                d = get_video(f, p["uniqueId"], v["id"])
            except FetchError as exc:
                errors.append(f"video {v['id']}: {exc}")
            try:
                pl = get_player_item(f, v["id"])
                d["accountRegion"] = pl.get("region")
                d["playerLocation"] = pl.get("location_created")
                if not d.get("locationCreated"):
                    d["locationCreated"] = pl.get("location_created")
                if d.get("likes") is None:
                    d["likes"] = pl.get("likes")
                if d.get("comments") is None:
                    d["comments"] = pl.get("comments")
                if d.get("shares") is None:
                    d["shares"] = pl.get("shares")
                if not d.get("storage_bucket"):
                    d["storage_bucket"] = pl.get("storage_bucket") or v.get("storage_bucket")
                if not d.get("sound") and pl.get("sound"):
                    d["sound"] = pl.get("sound")
            except FetchError as exc:
                errors.append(f"player api {v['id']}: {exc}")
            details[v["id"]] = d

    verification = []
    F = p["stats"].get("followerCount") or 0
    if p["status"] == "ok" and p.get("id"):
        try:
            wb = get_webcast_user(f, p["id"])
            if wb.get("followers") is not None:
                verification.append(
                    {
                        "field": "followerCount_vs_webcast_api",
                        "values": [F, wb["followers"]],
                        "status": "VERIFIED" if _close(F, wb["followers"], 0.002, 3) else "MISMATCH",
                        "note": "Webcast API cross-check",
                    }
                )
        except FetchError as exc:
            errors.append(f"webcast api: {exc}")

    merged = []
    for v in vids:
        d = details.get(v["id"]) or {}
        row = {**v, **d}
        row["opened"] = bool(d.get("opened"))
        merged.append(row)

    opened = [m for m in merged if m.get("opened")]
    with_views = [m for m in merged if (m.get("views") or 0) > 0]
    views_list = [m["views"] for m in with_views]
    med_views = _med(views_list)
    med_reach = _pct(_med([x / F for x in views_list])) if F and views_list else None
    med_likes_view = _pct(_med([m["likes"] / m["views"] for m in with_views if m.get("likes") is not None]))
    restricted = [
        m["id"]
        for m in opened
        if (m.get("moderation") or {}).get("isProhibited")
        or (m.get("moderation") or {}).get("takeDown")
        or ((m.get("moderation") or {}).get("displayPenaltyType") or 0) != 0
    ]

    jail_count = sum(1 for m in with_views if (m.get("views") or 0) <= 350)
    copyrighted = sum(1 for m in opened if (m.get("sound") or {}).get("copyrighted"))
    suggested_cnt = sum(1 for m in opened if m.get("suggestedWords"))
    sig = p.get("signature") or ""
    has_email = bool(re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", sig, re.I))
    recent_rename = bool(p.get("uniqueIdModifyTime") and time.time() - p["uniqueIdModifyTime"] < 90 * 86400)

    trust_items = [
        {"axis": "تطابق المصادر المستقلة", "points": 20 if all(v["status"] == "VERIFIED" for v in verification) else 10, "max": 20},
        {"axis": "خلو الحساب من القيود", "points": 20 if not restricted and p["status"] == "ok" else 10, "max": 20},
        {"axis": "استقرار المعرّف (90 يوماً)", "points": 8 if recent_rename else 20, "max": 20},
        {"axis": "توازن الوصول مقابل المتابعين", "points": 20 if not (med_reach is not None and F >= 10000 and med_reach < 1.0) else 8, "max": 20},
        {"axis": "نظافة البايو من الانكشاف", "points": 12 if has_email else 20, "max": 20},
    ]
    trust_points = sum(x["points"] for x in trust_items)

    diagnostics = [
        {"id": "account_check", "title": "Account Check · فحص الحساب", "status": "pass" if p.get("id") else "unknown", "tier": "CONFIRMED", "detail": f"ID: {p.get('id') or '—'}"},
        {"id": "account_status", "title": "Account Status · الحالة", "status": "pass" if p["status"] == "ok" and not p["private"] and not restricted else "warn", "tier": "CONFIRMED", "detail": f"{p['status']} · {'Private' if p['private'] else 'Public'}"},
        {"id": "sound_copyright", "title": "Sound & Copyright · الصوت", "status": "unknown" if not opened else "warn" if copyrighted else "pass", "tier": "CONFIRMED", "detail": f"محمي: {copyrighted}/{len(opened)}"},
        {"id": "fyp_eligibility", "title": "For You Feed · أهلية لك", "status": "fail" if p["private"] or restricted else "unknown" if not opened else "pass", "tier": "ESTIMATE", "detail": f"مفهرس بحثياً: {suggested_cnt}/{len(opened)}"},
        {"id": "shadowban", "title": "Shadowban · تقييد الوصول", "status": "unknown" if len(with_views) < 2 else "fail" if restricted else "warn" if (med_reach is not None and F >= 1000 and med_reach < 1.0) else "pass", "tier": "ESTIMATE", "detail": f"الوصول: {med_reach if med_reach is not None else '—'}%"},
        {"id": "view_jail", "title": "200–300 View Jail · عتبة المشاهدات", "status": "unknown" if not with_views else "warn" if jail_count >= max(1, len(with_views) // 2) else "pass", "tier": "DERIVED", "detail": f"ضمن ≤350: {jail_count}/{len(with_views)}"},
        {"id": "trust_score", "title": "Trust Score · مؤشر الثقة", "status": "pass" if trust_points >= 75 else "warn" if trust_points >= 50 else "fail", "tier": "ESTIMATE", "detail": f"{trust_points}/100"},
        {"id": "security_checkup", "title": "Security Checkup · الأمان", "status": "warn" if (has_email or recent_rename) else "pass", "tier": "CONFIRMED", "detail": f"بريد مكشوف: {'نعم' if has_email else 'لا'}"},
    ]

    acc_regions = [m["accountRegion"] for m in merged if m.get("accountRegion")]
    up_countries: dict[str, int] = {}
    vid_buckets: dict[str, int] = {}
    for m in merged:
        if m.get("locationCreated"):
            up_countries[m["locationCreated"]] = up_countries.get(m["locationCreated"], 0) + 1
        if m.get("storage_bucket"):
            vid_buckets[m["storage_bucket"]] = vid_buckets.get(m["storage_bucket"], 0) + 1

    dom_region = max(set(acc_regions), key=acc_regions.count) if acc_regions else None
    dom_upload = max(up_countries, key=lambda k: up_countries[k]) if up_countries else None

    return {
        "username": p["uniqueId"],
        "collected_at": iso(p["fetched_at"]),
        "collection_status": "partial" if (errors or f.log) else "collected" if p.get("id") else "unavailable",
        "vpn_status": "not_determinable",
        "profile": {
            "user_id": p["id"],
            "uniqueId": p["uniqueId"],
            "nickname": p["nickname"],
            "status": p["status"],
            "verified": p["verified"],
            "private": p["private"],
            "followers": p["stats"]["followerCount"],
            "following": p["stats"]["followingCount"],
            "total_likes": p["stats"]["heartCount"],
            "videos": p["stats"]["videoCount"],
            "account_created": iso(p["createTime"]),
            "avatar_bucket": p.get("avatar_bucket"),
            "upload_countries": up_countries,
            "storage_buckets_videos": vid_buckets,
            "restricted_videos": restricted,
        },
        "region": {
            "account_region": dom_region,
            "dominant_upload_country": dom_upload,
            "upload_countries": up_countries,
            "storage_buckets_videos": vid_buckets,
        },
        "derived": {
            "median_views": med_views,
            "median_views_per_follower_pct": med_reach,
            "median_likes_per_view_pct": med_likes_view,
        },
        "verification": verification,
        "diagnostics": diagnostics,
        "trust_score_0_100": trust_points,
        "trust_breakdown": trust_items,
        "videos": merged,
        "errors": errors + f.log,
        "limitations": LIMITATIONS_AR,
    }


def web() -> None:
    import streamlit as st

    st.set_page_config(page_title="waf3 — منصة فحص تيك توك", layout="wide")
    st.markdown(
        """
        <style>
        .stApp, [data-testid="stAppViewContainer"] {
            direction: rtl;
            text-align: right;
            background-color: #0e1117 !important;
            color: #f8fafc !important;
        }
        [data-testid="stHeader"] {
            background-color: #0e1117 !important;
        }
        h1, h2, h3, h4, p, label, span, div, .stMarkdown {
            color: #f8fafc !important;
        }
        .stCaption, small {
            color: #94a3b8 !important;
        }
        input, textarea, pre, code {
            direction: ltr;
            text-align: left;
            color: #f8fafc !important;
            background-color: #161b26 !important;
        }
        div[data-testid="stMetric"] {
            background: #161b26 !important;
            border: 1px solid #2a3346 !important;
            padding: 14px 16px;
            border-radius: 12px;
        }
        div[data-testid="stMetricValue"], div[data-testid="stMetricLabel"] {
            color: #f8fafc !important;
        }
        .stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {
            background-color: #e11d48 !important;
            color: #ffffff !important;
            border: none !important;
            border-radius: 8px !important;
        }
        .stButton > button:hover, .stFormSubmitButton > button:hover, .stDownloadButton > button:hover {
            background-color: #be123c !important;
            color: #ffffff !important;
        }
        button[data-baseweb="tab"] {
            color: #cbd5e1 !important;
        }
        button[data-baseweb="tab"][aria-selected="true"] {
            color: #ffffff !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.title("waf3 — منصة فحص حسابات تيك توك الحديثة")
    st.caption("فحص شامل بـ 8 محاور تشخيصية + فاحص اليوزرات + محلل الفيديو والصوت + مقارنة حسابين.")

    key = os.environ.get("WAF3_ACCESS_KEY", "")
    if key and not hmac.compare_digest(st.text_input("رمز الدخول", type="password").encode(), key.encode()):
        st.stop()

    t1, t2, t3, t4 = st.tabs(["الفحص الشامل (8 محاور)", "فاحص اليوزرات", "محلل الفيديو والصوت", "مقارنة حسابين"])

    with t1:
        with st.form("scan_form"):
            c_in, c_btn = st.columns([4, 1])
            user = c_in.text_input("اسم المستخدم (بدون رابط)", placeholder="مثال: tiktok", max_chars=25).strip().lstrip("@")
            submit = c_btn.form_submit_button("بدء الفحص", type="primary", use_container_width=True)
        if submit:
            if not re.fullmatch(r"[A-Za-z0-9_.]{1,24}", user):
                st.error("اسم المستخدم غير صالح")
            else:
                with st.spinner("جارٍ جمع البيانات وفحص المحاور الثمانية..."):
                    try:
                        st.session_state["report"] = audit(user)
                    except Exception as exc:
                        st.error(str(exc))

        r = st.session_state.get("report")
        if r:
            p = r["profile"]
            k1, k2, k3, k4, k5 = st.columns(5)
            k1.metric("المتابعون", f"{p['followers']:,}" if p["followers"] is not None else "—")
            k2.metric("يتابِع", f"{p['following']:,}" if p["following"] is not None else "—")
            k3.metric("الإعجابات", f"{p['total_likes']:,}" if p["total_likes"] is not None else "—")
            k4.metric("الفيديوهات", f"{p['videos']:,}" if p["videos"] is not None else "—")
            k5.metric("Trust Score", f"{r['trust_score_0_100']}/100")

            st.subheader("نتائج المحاور الـ 8")
            cols = st.columns(2)
            for idx, mod in enumerate(r["diagnostics"]):
                badge = "سليم" if mod["status"] == "pass" else "تنبيه" if mod["status"] == "warn" else "مقيد" if mod["status"] == "fail" else "غير متاح"
                cols[idx % 2].markdown(
                    f"**{mod['title']}** — `{badge}` (`{mod['tier']}`)  \n{mod['detail']}"
                )

            st.subheader("تفصيل مؤشر الثقة")
            for item in r["trust_breakdown"]:
                st.progress(item["points"] / item["max"], text=f"{item['axis']}: {item['points']}/{item['max']}")

            with st.expander("البيانات الخام (JSON) والتحميل"):
                text = json.dumps(r, ensure_ascii=False, indent=2)
                st.download_button("تنزيل تقرير JSON", text, file_name=f"waf3-{r['username']}.json", mime="application/json")
                st.json(r)

    with t2:
        col_g1, col_g2 = st.columns([3, 1])
        base = col_g1.text_input("توليد صيغ مقترحة من كلمة أساسية", placeholder="qabas")
        if col_g2.button("توليد 8 صيغ", use_container_width=True) and base.strip():
            clean = re.sub(r"[^A-Za-z0-9_.]", "", base.strip().lstrip("@").lower())
            st.session_state["u_list"] = "\n".join([clean, f"{clean}.official", f"{clean}_sa", f"the.{clean}", f"its.{clean}", f"{clean}_", f"_{clean}", f"{clean}1"])

        raw_handles = st.text_area("قائمة اليوزرات (حتى 8)", value=st.session_state.get("u_list", ""))
        if st.button("فحص اليوزرات", type="primary"):
            handles = [x for x in re.split(r"[\s,]+", raw_handles.strip()) if x]
            if not handles:
                st.warning("أدخل اسماً واحداً على الأقل")
            else:
                with st.spinner("جارٍ التحقق..."):
                    res = check_usernames(handles)
                    st.dataframe(res, use_container_width=True)
                    buf = io.StringIO()
                    writer = csv.DictWriter(buf, fieldnames=list(res[0].keys()))
                    writer.writeheader()
                    writer.writerows(res)
                    st.download_button("تصدير CSV", buf.getvalue(), file_name="waf3-usernames.csv", mime="text/csv")

    with t3:
        vid_url = st.text_input("رابط أو معرف الفيديو", placeholder="https://www.tiktok.com/@tiktok/video/7400000000000000000")
        if st.button("تحليل الفيديو", type="primary"):
            try:
                with st.spinner("جارٍ تحليل الفيديو والصوت..."):
                    st.json(inspect_video(vid_url))
            except Exception as exc:
                st.error(str(exc))

    with t4:
        ca, cb = st.columns(2)
        u_a = ca.text_input("الحساب الأول", placeholder="tiktok").strip().lstrip("@")
        u_b = cb.text_input("الحساب الثاني", placeholder="khaby.lame").strip().lstrip("@")
        if st.button("بدء المقارنة", type="primary"):
            if not u_a or not u_b:
                st.warning("أدخل اسمي المستخدمين أولاً")
            else:
                with st.spinner("جارٍ مقارنة الحسابين..."):
                    try:
                        ra, rb = audit(u_a), audit(u_b)
                        st.dataframe(
                            [
                                {"المعيار": "المتابعون", u_a: ra["profile"]["followers"], u_b: rb["profile"]["followers"]},
                                {"المعيار": "وسيط المشاهدات", u_a: ra["derived"]["median_views"], u_b: rb["derived"]["median_views"]},
                                {"المعيار": "الوصول / المتابعين %", u_a: ra["derived"]["median_views_per_follower_pct"], u_b: rb["derived"]["median_views_per_follower_pct"]},
                                {"المعيار": "Trust Score", u_a: ra["trust_score_0_100"], u_b: rb["trust_score_0_100"]},
                            ],
                            use_container_width=True,
                        )
                    except Exception as exc:
                        st.error(str(exc))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        try:
            if len(sys.argv) != 3:
                raise ValueError("Expected username")
            print(json.dumps(audit(sys.argv[2]), ensure_ascii=False))
        except Exception as exc:
            print(json.dumps({"fatal_error": str(exc)}, ensure_ascii=False))
            sys.exit(1)
    elif len(sys.argv) > 1 and sys.argv[1] == "--check-usernames":
        print(json.dumps(check_usernames(sys.argv[2:]), ensure_ascii=False, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--video":
        if len(sys.argv) != 3:
            print("Usage: python waf3.py --video URL_OR_ID", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(inspect_video(sys.argv[2]), ensure_ascii=False, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--compare":
        if len(sys.argv) != 4:
            print("Usage: python waf3.py --compare USER_A USER_B", file=sys.stderr)
            sys.exit(1)
        print(json.dumps({"a": audit(sys.argv[2]), "b": audit(sys.argv[3])}, ensure_ascii=False, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--leaderboard":
        if len(sys.argv) < 3:
            print("Usage: python waf3.py --leaderboard USER1 USER2 ...", file=sys.stderr)
            sys.exit(1)
        f = Fetcher()
        board = []
        for raw_u in sys.argv[2:8]:
            u = raw_u.strip().lstrip("@")
            try:
                p = get_profile(f, u)
                st_p = p.get("stats", {})
                board.append({
                    "username": p.get("uniqueId", u),
                    "status": p.get("status"),
                    "followers": st_p.get("followerCount"),
                    "total_likes": st_p.get("heartCount"),
                    "videos": st_p.get("videoCount"),
                    "verified": p.get("verified"),
                })
            except Exception as exc:
                board.append({"username": u, "error": str(exc)})
        board.sort(key=lambda r: r.get("followers") or -1, reverse=True)
        print(json.dumps(board, ensure_ascii=False, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--permissions":
        if len(sys.argv) < 3:
            print("Usage: python waf3.py --permissions USER1 USER2 ...", file=sys.stderr)
            sys.exit(1)
        f = Fetcher()
        perms = []
        for raw_u in sys.argv[2:6]:
            u = raw_u.strip().lstrip("@")
            try:
                p = get_profile(f, u)
                perms.append({
                    "username": p.get("uniqueId", u),
                    "is_live": bool(p.get("room_id")),
                    "tt_seller": p.get("tt_seller"),
                    "download_allowed": None if p.get("download_setting") is None else p.get("download_setting") == 0,
                    "open_favorite": p.get("open_favorite"),
                    "following_hidden": None if p.get("following_visibility") is None else p.get("following_visibility") == 2,
                    "embed_banned": p.get("embed_banned"),
                })
            except Exception as exc:
                perms.append({"username": u, "error": str(exc)})
        print(json.dumps(perms, ensure_ascii=False, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--batch-videos":
        if len(sys.argv) < 3:
            print("Usage: python waf3.py --batch-videos URL_OR_ID ...", file=sys.stderr)
            sys.exit(1)
        batch_out = []
        for raw_v in sys.argv[2:8]:
            try:
                batch_out.append(inspect_video(raw_v))
            except Exception as exc:
                batch_out.append({"input": raw_v, "error": str(exc)})
        print(json.dumps(batch_out, ensure_ascii=False, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--snowflake":
        if len(sys.argv) < 3:
            print("Usage: python waf3.py --snowflake ID_OR_URL...", file=sys.stderr)
            sys.exit(1)
        decoded = []
        for tok in sys.argv[2:]:
            m = re.search(r"(\d{15,22})", tok)
            vid = m.group(1) if m else tok
            ts = id_to_unix(vid)
            decoded.append({"id": vid, "unix": ts, "utc": iso(ts)})
        print(json.dumps(decoded, ensure_ascii=False, indent=2))
    else:
        web()
