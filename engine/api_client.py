# -*- coding: utf-8 -*-
"""南方科技大学场馆预约系统 API 客户端。

认证模型（从前端 JS 逆向确认）：
  微信(企业微信互通) OAuth 拿到 code -> GET /api/blade-app/qywx/getUserIdByCode?code=
  -> {userid, token}；之后所有接口以 userid+token 查询参数鉴权。
"""
from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

from captcha import build_check_body, decode_dataurl, solve_slider

BASE = "https://reservation.sustech.edu.cn"
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.49")


class ApiError(Exception):
    def __init__(self, code: Any, msg: str, data: Any = None):
        super().__init__(f"[{code}] {msg}")
        self.code = code
        self.msg = msg
        self.data = data


class AuthError(ApiError):
    """userid/token 失效。"""


def _extract_code(text: str) -> str | None:
    text = text.strip()
    m = re.search(r"[?&]code=([0-9a-zA-Z_-]+)", text)
    if m:
        return m.group(1)
    # 允许直接粘贴纯 code
    if re.fullmatch(r"[0-9a-zA-Z_-]{10,}", text):
        return text
    return None


class SustechClient:
    def __init__(self, userid: str | None = None, token: str | None = None):
        self.userid = userid
        self.token = token
        self.customer_id: str | None = None
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        # 登录态可能被服务端轮换：任何响应里带上新 userid/token 时自动更新，
        # 并通过 on_session_update 通知外层持久化（与站点前端 SET_USER 行为一致）
        self.on_session_update = None
        self.login_debug: dict = {}

    # ---------- 会话管理 ----------

    def set_cookies(self, cookies: dict | None):
        for k, v in (cookies or {}).items():
            self.session.cookies.set(k, v)

    def export_cookies(self) -> dict:
        return requests.utils.dict_from_cookiejar(self.session.cookies)

    def _capture_session_fields(self, data) -> bool:
        """响应数据若带用户记录（可能被服务端轮换 token），更新本地会话。
        与站点前端 SET_USER(data) 行为一致：token 取 data.token，userid 取 wxOpenid。"""
        if not isinstance(data, dict) or not data.get("token"):
            return False
        new_tok = str(data.get("token") or "")
        new_uid = data.get("wxOpenid") or data.get("userid") or data.get("userId")
        changed = False
        if new_tok and new_tok != self.token:
            self.token = new_tok
            changed = True
        if new_uid and str(new_uid) != str(self.userid):
            self.userid = str(new_uid)
            changed = True
        if changed and self.on_session_update:
            try:
                self.on_session_update(self)
            except Exception:
                pass
        return changed

    # ---------- 基础请求 ----------

    def request(self, method: str, path: str, *, params: dict | None = None,
                json_body: dict | None = None, form: bool = False,
                timeout: float = 10.0, retry: int = 1) -> Any:
        params = dict(params or {})
        url = BASE + path
        last_exc: Exception | None = None
        for attempt in range(retry + 1):
            try:
                if form:
                    r = self.session.post(url, params=params,
                                          headers={"Content-Type": "application/x-www-form-urlencoded;"},
                                          data=json_body or {}, timeout=timeout)
                elif json_body is not None:
                    r = self.session.post(url, params=params, json=json_body, timeout=timeout)
                else:
                    r = self.session.request(method, url, params=params, timeout=timeout)
                try:
                    data = r.json()
                except ValueError:
                    raise ApiError(r.status_code, f"非 JSON 响应: {r.text[:120]}")
                if isinstance(data, dict) and data.get("code") == 200:
                    self._capture_session_fields(data.get("data"))
                return data
            except (requests.ConnectionError, requests.Timeout) as e:
                last_exc = e
                if attempt < retry:
                    time.sleep(0.3)
                    continue
                raise ApiError("NETWORK", f"网络错误: {e}")
        raise last_exc  # pragma: no cover

    @staticmethod
    def _check(data: dict) -> Any:
        code = data.get("code")
        if code == 200:
            return data.get("data")
        msg = str(data.get("msg") or data.get("message") or "")
        if "鉴权失败" in msg:
            raise AuthError(code, msg, data)
        raise ApiError(code, msg, data)

    def authed(self, extra: dict | None = None) -> dict:
        p = {"userid": self.userid, "token": self.token}
        if extra:
            p.update(extra)
        return p

    # ---------- 登录 ----------

    def login_by_url(self, text: str) -> dict:
        code = _extract_code(text)
        if not code:
            raise ApiError("INPUT", "未在输入中找到 OAuth code（应包含 code=... 参数）")
        url = BASE + "/api/blade-app/qywx/getUserIdByCode?" + requests.utils.requote_uri(f"code={code}")
        resp = self.session.get(url, timeout=10)
        try:
            data = resp.json()
        except ValueError:
            raise ApiError("PARSE", f"登录响应非 JSON: {resp.text[:150]}")
        self.login_debug = {
            "httpStatus": resp.status_code,
            "setCookies": resp.headers.get("Set-Cookie"),
            "cookies": requests.utils.dict_from_cookiejar(self.session.cookies),
            "rawBody": resp.text[:2000],
        }
        if data.get("code") != 200:
            msg = str(data.get("msg") or "")
            if "invalid code" in msg or "获取userid失败" in msg:
                raise ApiError(
                    data.get("code"),
                    "code 无效（最常见原因：在企业微信里打开过页面，code 已被页面用掉；"
                    "或已超过 5 分钟）。请按页面上的「扫码获取新链接」流程重新复制，"
                    "复制前不要让预约场馆页加载完成")
            raise ApiError(data.get("code"), msg)
        d = data.get("data") or {}
        # 关键：接口的 userid 参数用 wxOpenid（学号），不是记录主键 id
        userid = d.get("wxOpenid") or d.get("userid") or d.get("userId") or d.get("id")
        token = d.get("token") or d.get("access_token")
        if not userid or not token:
            raise ApiError("PARSE", f"登录响应中缺少 userid/token: {json.dumps(d, ensure_ascii=False)[:300]}")
        self.userid, self.token = str(userid), str(token)
        self.customer_id = str(d.get("id") or "")
        return d

    # ---------- 用户 / 基础数据 ----------

    def get_user_info(self) -> dict:
        return self._check(self.request("GET", "/api/blade-app/qywx/getUserInfoByUserid",
                                        params=self.authed()))

    def get_gyms(self) -> list[dict]:
        d = self._check(self.request("GET", "/api/blade-app/qywx/getAppGymPageByCustomerId",
                                     params=self.authed({"current": 1, "size": 100})))
        return (d or {}).get("records") or [] if isinstance(d, dict) else (d or [])

    def get_grounds(self, gym_id: str) -> list[dict]:
        # 注意：不能带 type 参数（type=2 是会议场地过滤，会把运动场地全部滤空）
        d = self._check(self.request("POST", "/api/blade-app/qywx/getAppGroundPageByGymId",
                                     params=self.authed({"gymId": gym_id, "current": 1,
                                                         "size": 100})))
        return (d or {}).get("records") or []

    def get_ground_detail(self, ground_id: str) -> dict:
        return self._check(self.request("GET", "/api/blade-app/qywx/getGroundDetailByParam",
                                        params=self.authed({"groundId": ground_id})))

    # 系统里按"今天起"计算档期的特殊场地（前端硬编码列表）
    SPECIAL_GROUNDS = {
        "1333325020650307585", "1333325132894076930", "1333325210870382593",
        "1333325286376243201", "1333325372158148610", "1333325451443077122",
        "1333325553058480129", "1333332194327822338",
    }

    def get_time_config(self, ground_id: str, max_day: int | None = None) -> dict:
        """时段配置。优先请求「今天→后天」三天；若系统不接受（部分场地今天不可约
        或日期越界返回「系统异常」），按阶梯收紧范围重试，UI 端对缺失日期做占位展示。"""
        from datetime import datetime, timedelta
        now = datetime.now()
        today = now.date()
        # 学校规则：后天在当天 20:00 开放。按此推算当前最大可约日，一次请求拿全
        # （减少无效请求次数，降低触发服务端限流的概率）。
        max_open = today + timedelta(days=2 if now.hour >= 20 else 1)
        candidates: list[tuple] = [
            (today, max_open),                       # 今天 → 当前最大可约日（一次到位）
            (max_open, max_open),                    # 仅最大可约日
            (today + timedelta(days=1), max_open),   # 明天 → 最大可约日
            (today, today),                          # 仅今天
        ]

        last_exc: ApiError | None = None
        seen = set()
        for s, e in candidates:
            if (s, e) in seen:
                continue
            seen.add((s, e))
            try:
                return self._check(self.request(
                    "GET", "/api/blade-app/qywx/getOrderTimeConfigList",
                    params=self.authed({"groundId": ground_id,
                                        "startDate": s.isoformat(), "endDate": e.isoformat()})))
            except ApiError as ex:
                last_exc = ex
                # 仅在"越界/系统异常"时收紧重试，其他错误（鉴权等）直接抛
                if "系统异常" not in str(ex.msg) and ex.code != 500:
                    raise
                time.sleep(0.3)
        raise last_exc or ApiError("SLOTS", "时段配置获取失败")

    def get_server_time(self) -> dict:
        return self._check(self.request("GET", "/api/blade-app/qywx/getSysTime",
                                        params=self.authed()))

    def is_blacklisted(self) -> bool:
        try:
            d = self._check(self.request("GET", "/api/blade-app/qywx/isGymBlackByCustomerId",
                                         params=self.authed()))
        except ApiError:
            return False
        return bool(d)

    # ---------- 订单 ----------

    def get_orders(self, current: int = 1, size: int = 20, **extra) -> list[dict]:
        d = self._check(self.request("GET", "/api/blade-app/qywx/getOrderPageListByParam",
                                     params=self.authed({"current": current, "size": size, **extra})))
        return (d or {}).get("records") or []

    def get_order_detail(self, order_id: str) -> dict:
        return self._check(self.request("POST", "/api/blade-app/qywx/getOrderDetailByParam",
                                        params=self.authed({"orderId": order_id}), form=True))

    def cancel_order(self, order: dict) -> dict:
        payload = dict(order)
        payload["status"] = 6
        return self._check(self.request("POST", "/api/blade-app/qywx/operatOrder",
                                        params=self.authed(), json_body=payload))

    # ---------- 验证码 ----------

    def solve_captcha(self, timeout: float = 10.0) -> str:
        """generate -> 自动求解 -> check，返回可用于 saveOrder 的凭证。失败抛 ApiError。"""
        d = self.request("POST", "/api/blade-base/captcha/generate/d", json_body={},
                         timeout=timeout)
        if not isinstance(d.get("captcha"), dict):
            msg = str(d.get("captcha") or d.get("msg") or "生成验证码失败")
            raise ApiError(d.get("code"), msg)
        cid, cap = d["id"], d["captcha"]
        if str(cap.get("type", "")).upper() != "SLIDER":
            raise ApiError("CAPTCHA", f"不支持的验证码类型: {cap.get('type')}")
        bg = decode_dataurl(cap["backgroundImage"])
        tpl = decode_dataurl(cap["templateImage"])
        answer, meta = solve_slider(bg, tpl)
        r = self.request("POST", "/api/blade-base/captcha/check/d",
                         json_body=build_check_body(cid, cap, answer), timeout=timeout)
        if r.get("code") != 200:
            raise ApiError(r.get("code"), f"验证码校验未通过({r.get('code')})", meta)
        return str(r.get("data") or "")

    # ---------- 下单 ----------

    def save_order(self, payload: dict, timeout: float = 8.0) -> dict:
        data = self.request("POST", "/api/blade-app/qywx/saveOrder",
                            params=self.authed(), json_body=payload, timeout=timeout)
        if data.get("code") == 200:
            return data.get("data") or {}
        raise ApiError(data.get("code"), str(data.get("msg") or "下单失败"), data)
