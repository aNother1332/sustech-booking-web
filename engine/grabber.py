# -*- coding: utf-8 -*-
"""抢场任务引擎。

时间轴（以开放时刻 T=当天 fire_time 为例）：
  T-120s  预检：鉴权、场地信息、黑名单、时钟同步
  T-45s   预解一个验证码凭证（generate 有 ~6s 频控，提前备好）
  T-15s   再备一个凭证（可选）
  T-lead  开始按 优先级组合 循环提交 saveOrder，直到成功/超窗/手动停止
"""
from __future__ import annotations

import collections
import re
import socket
import threading
import time
import uuid
from datetime import date as date_cls
from datetime import datetime, timedelta

from api_client import ApiError, AuthError, SustechClient

FIRE_LEAD_DEFAULT_MS = 80
DEFAULT_WINDOW_S = 240
DEFAULT_ATTEMPT_INTERVAL_S = 0.35
CAPTCHA_PACE_S = 6.0          # generate 接口实测频控约 5-7s


def _now_ms() -> float:
    return time.time() * 1000


class Ntp:
    SERVERS = ["ntp.aliyun.com", "ntp.tencent.com", "cn.pool.ntp.org"]

    @staticmethod
    def query(server: str, timeout: float = 2.0) -> float | None:
        try:
            port = 123
            buf = b"\x1b" + 47 * b"\0"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(buf, (server, port))
                data, _ = s.recvfrom(512)
        except OSError:
            return None
        if len(data) < 48:
            return None
        secs = int.from_bytes(data[40:44], "big")
        frac = int.from_bytes(data[44:48], "big")
        return (secs - 2208988800) + frac / (1 << 32)  # unix seconds (UTC)


class GrabTask:
    STATUSES = ("pending", "preflight", "waiting_login", "armed", "firing", "success",
                "failed", "expired", "cancelled", "dryrun_done")

    def __init__(self, config: dict, client: SustechClient):
        self.id = uuid.uuid4().hex[:10]
        self.config = config
        self.client = client
        # webapp 注入：返回 store 里最新的 (userid, token)，token 失效后可热更新
        self.session_loader: Any = None
        # webapp 注入：token 失效时立即通知前端（让界面马上提示重新登录）
        self.auth_fail_hook: Any = None
        self.status = "pending"
        self.created_at = time.time()
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.result: dict = {}
        self.logs: collections.deque = collections.deque(maxlen=3000)
        self.attempts: list[dict] = []
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self._log_seq = 0
        self._lock = threading.Lock()

    # ---------- 日志 ----------

    def log(self, msg: str, level: str = "info"):
        with self._lock:
            self._log_seq += 1
            seq = self._log_seq
        self.logs.append({"seq": seq, "ts": time.time(), "level": level, "msg": msg})

    def snapshot(self) -> dict:
        return {
            "id": self.id,
            "config": self.config,
            "status": self.status,
            "createdAt": self.created_at,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "result": self.result,
            "logs": list(self.logs)[-400:],
            "attempts": self.attempts[-100:],
        }

    # ---------- 目标时间 ----------

    def target_date(self) -> str:
        cfg = self.config
        if cfg.get("date_mode") == "fixed" and cfg.get("fixed_date"):
            return cfg["fixed_date"]
        d = date_cls.today() + timedelta(days=2)
        return d.strftime("%Y-%m-%d")

    def fire_epoch_ms(self) -> float:
        """返回本地时钟意义上的开抢时刻（epoch ms）。"""
        hh, mm, ss = [int(x) for x in str(self.config.get("fire_time", "20:00:00")).split(":")]
        d = datetime.now().replace(hour=hh, minute=mm, second=ss, microsecond=0)
        return d.timestamp() * 1000

    # ---------- 主流程 ----------

    def start(self):
        self.thread = threading.Thread(target=self.run, name=f"grab-{self.id}", daemon=True)
        self.thread.start()

    def stop(self, status="cancelled", note="手动停止"):
        self.stop_event.set()
        if self.status in ("pending", "preflight", "armed", "firing"):
            self.status = status
            self.finished_at = time.time()
            self.log(note, "warn")

    # 时钟同步：优先 getSysTime（需登录），失败用 NTP
    def _sync_clock(self) -> float:
        offsets: list[float] = []
        rtts: list[float] = []
        for _ in range(5):
            if self.stop_event.is_set():
                break
            t0 = time.time()
            pc0 = time.perf_counter()
            try:
                data = self.client.get_server_time()
            except ApiError as e:
                self.log(f"getSysTime 不可用（{e.msg}），改用 NTP", "warn")
                break
            pc1 = time.perf_counter()
            srv_ms = self._parse_server_time(data)
            if srv_ms is None:
                break
            t1 = t0 + (pc1 - pc0)
            rtt = (pc1 - pc0) * 1000
            rtts.append(rtt)
            offsets.append(srv_ms - (t0 + t1) / 2 * 1000)
            time.sleep(0.12)
        if len(offsets) >= 3:
            med_rtt = sorted(rtts)[len(rtts) // 2]
            good = [o for o, r in zip(offsets, rtts) if r <= med_rtt * 2 + 50]
            off = sorted(good or offsets)[len(good or offsets) // 2]
            self.log(f"服务器时钟同步完成：偏移 {off:+.0f}ms（RTT中位 {med_rtt:.0f}ms）")
            return off
        ntp_offs = []
        for srv in Ntp.SERVERS:
            t = Ntp.query(srv)
            if t:
                ntp_offs.append(t * 1000 - _now_ms())
                if len(ntp_offs) >= 2:
                    break
        if ntp_offs:
            off = sorted(ntp_offs)[len(ntp_offs) // 2]
            self.log(f"NTP 同步：偏移 {off:+.0f}ms（{srv}）", "warn")
            return off
        self.log("时钟同步失败，使用本机时间", "warn")
        return 0.0

    @staticmethod
    def _parse_server_time(data) -> float | None:
        return _parse_server_time_impl_impl(data)

    def _refresh_creds(self):
        """从 store 读取最新登录态（用户可能重新扫码登录过），必要时切换。"""
        if not self.session_loader:
            return False
        try:
            creds = self.session_loader()
        except Exception:
            return False
        if not creds:
            return False
        uid, tok = creds
        if uid and tok and (str(uid) != str(self.client.userid) or str(tok) != str(self.client.token)):
            self.client.userid, self.client.token = str(uid), str(tok)
            self.log("已应用最新登录态（重新登录成功）", "success")
            return True
        return False

    def _preflight_with_login_wait(self, fire_local: float) -> bool:
        """预检；若 token 失效（实测约 10 分钟有效期），进入等待重新登录状态，
        每 5 秒重试，直到抢场前 30 秒仍无效才放弃。返回是否可继续。"""
        deadline = fire_local - 30_000
        warned = False
        while not self.stop_event.is_set():
            self._refresh_creds()
            try:
                self._preflight()
                if self.status in ("failed", "cancelled"):
                    return False
                return True
            except AuthError:
                if _now_ms() >= deadline:
                    self.status = "failed"
                    self.result["error"] = ("登录已过期且未能重新登录。token 有效期实测约 10 分钟，"
                                            "请在首页重新扫码登录后再建任务。")
                    self.log(self.result["error"], "error")
                    return False
                if not warned:
                    self.status = "waiting_login"
                    if self.auth_fail_hook:
                        try: self.auth_fail_hook()
                        except Exception: pass
                    self.log("⚠ 登录已过期（token 有效期实测约 10 分钟）。请立即在首页点「生成登录二维码」"
                             "重新扫码登录，本任务会自动使用新登录态继续；否则开抢时将中止。"
                             f"（等待至 {datetime.fromtimestamp(deadline/1000).strftime('%H:%M:%S')}）", "error")
                    warned = True
                remaining = max(0, (deadline - _now_ms()) / 1000)
                self.stop_event.wait(min(5, remaining))
        return False

    def run(self):
        cfg = self.config
        self.started_at = time.time()
        self.log(f"任务启动：目标日期 {self.target_date()}，开抢 {cfg.get('fire_time')}，"
                 f"演练={'是' if cfg.get('dry_run') else '否'}")
        try:
            # ---- 等待到 T-130s ----
            fire_local = self.fire_epoch_ms()
            while not self.stop_event.is_set():
                remain = fire_local - _now_ms()
                if remain <= 130_000:
                    break
                self.status = "pending"
                self._refresh_creds()
                if remain > 600_000:
                    self.stop_event.wait(30)
                else:
                    self.stop_event.wait(min(5, remain / 1000 + 0.01))
            if self.stop_event.is_set():
                return

            # ---- 预检（含等待重新登录） ----
            self.status = "preflight"
            if not self._preflight_with_login_wait(fire_local):
                return

            offset = self._sync_clock()
            self.result["clockOffsetMs"] = offset

            # ---- 预解验证码（在时间允许内尽量多备：验证码接口约 6s 频控，
            #      多备几枚可以让开抢瞬间的多次尝试不受频控拖慢）----
            presolved: list[str] = []
            self._presolve_loop(presolved, fire_local, offset)

            # ---- 压秒等待 ----
            self.status = "armed"
            self._refresh_creds()
            lead = float(cfg.get("lead_ms", FIRE_LEAD_DEFAULT_MS))
            target = fire_local - offset - lead
            self.log(f"就绪，将于服务器时间 {cfg.get('fire_time')} 触发"
                     f"（提前 {lead:.0f}ms 发出，本机等待至 {datetime.fromtimestamp(target/1000).strftime('%H:%M:%S.%f')[:-3]}）")
            while not self.stop_event.is_set():
                remain = target - _now_ms()
                if remain <= 0:
                    break
                if remain > 2000:
                    self.stop_event.wait(0.5)
                else:
                    pass  # 忙等保证精度
            if self.stop_event.is_set():
                self.status = "cancelled"
                return

            # ---- 开抢 ----
            self.status = "firing"
            self._fire_loop(presolved)
        except AuthError as e:
            self.status = "failed"
            self.result["error"] = f"登录态失效：{e.msg}。请重新扫码登录（token 有效期实测约 10 分钟）。"
            self.log(self.result["error"], "error")
            if self.auth_fail_hook:
                try: self.auth_fail_hook()
                except Exception: pass
        except Exception as e:  # noqa: BLE001
            self.status = "failed"
            self.result["error"] = f"任务异常: {e!r}"
            self.log(self.result["error"], "error")
        finally:
            if self.finished_at is None:
                self.finished_at = time.time()

    # ---------- 阶段实现 ----------

    def _preflight(self):
        cfg = self.config
        try:
            user = self.client.get_user_info()
            self.result["user"] = user or {}
            self.log(f"登录态正常：{user.get('name') or user.get('customerName') or self.client.userid}")
        except AuthError:
            raise
        except ApiError as e:
            self.log(f"用户信息获取失败：{e.msg}", "warn")
        if self.client.is_blacklisted():
            self.status = "failed"
            self.result["error"] = "账号在场馆黑名单中，无法预约"
            self.log(self.result["error"], "error")
            return
        # 场地信息（按候选项中的场地去重）
        details = {}
        seen_gid = set()
        for p in cfg.get("pairs", []):
            gid = p.get("groundId")
            if gid in seen_gid:
                continue
            seen_gid.add(gid)
            try:
                d = self.client.get_ground_detail(gid)
                details[gid] = d or {}
            except ApiError as e:
                self.log(f"场地 {p.get('groundName')} 详情获取失败：{e.msg}", "warn")
        self.result["groundDetails"] = details

        # 学校规则：一人一天最多 2 小时 —— 读取目标日已有预约，剔除会超限的候选项
        target = self.target_date()
        booked = self._booked_hours(target)
        self.result["bookedHours"] = booked
        if booked is None:
            self.log("未能读取当日已有预约，跳过 2 小时上限校验", "warn")
        else:
            remaining = max(0.0, self.MAX_HOURS_PER_DAY - booked)
            self.log(f"目标日 {target} 已约 {booked:g} 小时，最多还能约 {remaining:g} 小时")
            kept = []
            for p in cfg.get("pairs", []):
                h = self._pair_hours(p)
                if h + booked <= self.MAX_HOURS_PER_DAY + 1e-6:
                    kept.append(p)
                else:
                    self.log(f"跳过 {p.get('groundName')} {p.get('start')}-{p.get('end')}"
                             f"（{h:g} 小时，将超过每日 {self.MAX_HOURS_PER_DAY:g} 小时上限）", "warn")
            if not kept:
                self.status = "failed"
                self.result["error"] = (f"目标日已约 {booked:g} 小时，所有候选项都会超过"
                                        f"每人每天 {self.MAX_HOURS_PER_DAY:g} 小时上限，任务中止")
                self.log(self.result["error"], "error")
                return
            cfg["pairs"] = kept
        # 「同时尝试其它场地」：扩展为同场馆同时段的其它可约场地
        self._expand_other_courts()
        self.log(f"预检完成：{len(cfg.get('pairs', []))} 个候选项")

    def _presolve_loop(self, bucket: list, fire_local: float, offset: float):
        """从 T-48s 到 T-8s，每 6.5 秒预解一枚验证码（上限 6 枚）。"""
        first_at = fire_local - 48_000 - offset
        deadline = fire_local - 8_000 - offset
        scheduled = first_at
        while not self.stop_event.is_set() and len(bucket) < 6:
            now = _now_ms()
            if now >= deadline:
                break
            if scheduled > now:
                self.stop_event.wait(min((scheduled - now) / 1000, 2.0))
                continue
            try:
                tok = self.client.solve_captcha()
                bucket.append(tok)
                self.log(f"预解验证码成功（缓存 {len(bucket)} 个）")
            except ApiError as e:
                self.log(f"预解验证码失败：{e.msg}", "warn")
            scheduled = max(scheduled + 6500, _now_ms() + 6500)

    @staticmethod
    def _pad_time(t: str) -> str:
        t = str(t or "")
        return ("0" + t) if 0 < t.find(":") < 2 else t

    def _pairs(self) -> list[dict]:
        """候选项（保持给定顺序；「同时尝试其它场地」的扩展在预检时完成）。"""
        return [dict(p) for p in (self.config.get("pairs") or [])]

    def _court_slot_open(self, court_id: str, date_str: str, start: str, end: str) -> bool:
        """对方场地在目标日、同一时段当前是否可约。
        目标日尚未开放（抢场模式）：所有场地开放后都是全新的，视为可约；
        目标日已开放（订场模式）：必须逐格核对 status==1，数据缺失则保守排除。"""
        try:
            cfg = self.client.get_time_config(court_id)
        except ApiError:
            return False
        cl = (cfg or {}).get("configList") or []
        day = next((x for x in cl if x.get("date") == date_str), None)
        if day is None:
            return str(self.config.get("date_mode")) == "auto_third_day"
        blocks = day.get("timeBlockList") or []
        started = False
        for b in blocks:
            t = self._pad_time(b.get("time"))
            if not started and t == start:
                started = True
            if started:
                if str(b.get("status")) != "1":
                    return False
                if self._pad_time(b.get("endTime")) == end:
                    return True
        return False

    def _expand_other_courts(self):
        """「同时尝试其它场地」：把候选项扩展为 本场馆 + 相同时段 的其它可约场地，
        顺序：先选中场地，其余按场号排序。"""
        cfg = self.config
        if not cfg.get("try_others"):
            return
        pairs = cfg.get("pairs") or []
        if not pairs:
            return
        base = pairs[0]
        target = self.target_date()
        details = (self.result.get("groundDetails") or {}).get(base.get("groundId")) or {}
        gym_id = details.get("gymId") or cfg.get("gym_id")
        try:
            courts = self.client.get_grounds(gym_id)
        except ApiError as e:
            self.log(f"获取场馆场地列表失败，无法扩展其它场地：{e.msg}", "warn")
            return

        def court_no(c: dict) -> int:
            m = re.search(r"\d+", str(c.get("name") or ""))
            return int(m.group()) if m else 999

        others = [c for c in courts
                  if str(c.get("id")) != str(base.get("groundId")) and str(c.get("status")) == "1"]
        others.sort(key=court_no)
        added = 0
        for c in others:
            if self.stop_event.is_set():
                return
            if self._court_slot_open(c["id"], target, base.get("start"), base.get("end")):
                pairs.append({"groundId": str(c["id"]), "groundName": c.get("name") or "",
                              "start": base.get("start"), "end": base.get("end")})
                added += 1
        self.log(f"已扩展 {added} 块同场馆同时段的场地作为候补（共 {len(pairs)} 个候选）")

    @staticmethod
    def _pair_hours(pair: dict) -> float:
        def to_min(t: str) -> int:
            h, m = str(t).split(":")
            return int(h) * 60 + int(m)
        return max(0.0, (to_min(pair.get("end", "0:00")) - to_min(pair.get("start", "0:00"))) / 60)

    def _booked_hours(self, date_str: str) -> float | None:
        """当日已约小时数（状态 1=待签到 / 2=已预约；取消/过期不计）。读取失败返回 None。"""
        try:
            orders = self.client.get_orders(1, 100)
        except ApiError:
            return None
        total = 0.0
        for o in orders or []:
            if str(o.get("status")) not in ("1", "2"):
                continue
            st = str(o.get("startTime") or "")
            en = str(o.get("endTime") or "")
            if not st.startswith(date_str):
                continue
            try:
                a = datetime.strptime(st[:19], "%Y-%m-%d %H:%M:%S")
                b = datetime.strptime(en[:19], "%Y-%m-%d %H:%M:%S")
                total += (b - a).total_seconds() / 3600
            except ValueError:
                continue
        return round(total, 2)

    MAX_HOURS_PER_DAY = 2.0  # 学校规则：一人一天最多预约 2 小时

    def _fire_loop(self, presolved: list):
        cfg = self.config
        window = float(cfg.get("window_seconds", DEFAULT_WINDOW_S)) * 1000
        interval = float(cfg.get("attempt_interval_ms", 400)) / 1000
        deadline = _now_ms() + window
        attempt_no = 0
        last_captcha_time = 0.0
        last_solve_failed = False

        def fresh_token():
            nonlocal last_captcha_time
            wait = CAPTCHA_PACE_S - (time.time() - last_captcha_time)
            if wait > 0 and presolved:
                pass  # 有缓存则不等待
            elif wait > 0:
                self.log(f"等待验证码频控 {wait:.1f}s")
                self.stop_event.wait(wait)
            tok = self.client.solve_captcha()
            last_captcha_time = time.time()
            return tok

        if cfg.get("dry_run"):
            pairs = self._pairs()
            self.log(f"【演练模式】共 {len(pairs)} 个候选项，将按此优先级依次模拟提交（不发真实请求）：")
            for p in pairs:
                if self.stop_event.is_set():
                    break
                tag = "抢场" if str(p.get("date_mode") or cfg.get("date_mode")) == "auto_third_day" else "订场"
                self.log(f"  演练[{tag}] -> {p.get('groundName')} {p.get('start')}-{p.get('end')}")
            self.status = "dryrun_done"
            self.result["dryRun"] = True
            self.log("演练完成：配置无误后可关闭演练模式正式抢场。")
            return

        ordered = self._pairs()
        while not self.stop_event.is_set():
            if _now_ms() > deadline:
                self.status = "expired"
                self.result["error"] = "抢购时间窗已结束，未抢到"
                self.log(self.result["error"], "error")
                return
            progressed = False
            for pair in ordered:
                if self.stop_event.is_set():
                    self.status = "cancelled"
                    return
                if _now_ms() > deadline:
                    break
                attempt_no += 1
                rec = {"no": attempt_no, "ground": pair.get("groundName"),
                       "slot": f"{pair.get('start')}-{pair.get('end')}", "t": time.time()}
                # 取验证码
                try:
                    if presolved:
                        tok = presolved.pop(0)
                    else:
                        tok = fresh_token()
                except ApiError as e:
                    rec["result"] = f"验证码失败: {e.msg}"
                    self.attempts.append(rec)
                    self.log(f"#{attempt_no} 验证码获取失败：{e.msg}", "warn")
                    last_solve_failed = True
                    self.stop_event.wait(1.0)
                    continue
                payload = self._build_payload(pair, tok)
                try:
                    t0 = time.perf_counter()
                    order = self.client.save_order(payload)
                    dt = (time.perf_counter() - t0) * 1000
                    rec["result"] = f"成功({dt:.0f}ms) orderNo={order.get('orderNo')}"
                    self.attempts.append(rec)
                    self.status = "success"
                    self.result["order"] = order
                    self.log(f"🎉 抢到了！{pair.get('groundName')} {pair.get('start')}-{pair.get('end')} "
                             f"订单号 {order.get('orderNo')}（耗时 {dt:.0f}ms）", "success")
                    return
                except AuthError:
                    if self._refresh_creds():
                        self.log(f"#{attempt_no} 登录态已更新，继续尝试", "warn")
                        continue
                    raise
                except ApiError as e:
                    msg = str(e.msg)
                    rec["result"] = f"{e.code}: {msg[:60]}"
                    self.attempts.append(rec)
                    if any(k in msg for k in ("已被预约", "已满", "无可用", "不可预约", "满员", "约满", "被抢")):
                        self.log(f"#{attempt_no} {pair.get('groundName')} {pair.get('start')}-{pair.get('end')} 已满，尝试下一候选")
                        progressed = True
                        continue
                    if "验证码" in msg:
                        self.log(f"#{attempt_no} 验证码被拒：{msg}，重取验证码", "warn")
                        self.stop_event.wait(0.4)
                        continue
                    if "频繁" in msg or "限流" in msg or "稍后再试" in msg:
                        self.log(f"#{attempt_no} 触发限流：{msg}，等待 3s", "warn")
                        self.stop_event.wait(3.0)
                        continue
                    if any(k in msg for k in ("未开放", "暂未开放", "未到", "开放时间", "预约时间", "不在")):
                        # 抢的就是 20:00 开放瞬间，首个请求可能比服务器开关早几十毫秒 → 快速重试
                        self.log(f"#{attempt_no} 尚未开放：{msg}，0.25s 后重试", "warn")
                        self.stop_event.wait(0.25)
                        continue
                    self.log(f"#{attempt_no} 未预期的响应 code={e.code} msg={msg}", "warn")
                    self.stop_event.wait(0.6)
                    continue
            if not progressed:
                self.stop_event.wait(interval)

    def _build_payload(self, pair: dict, captcha_token: str) -> dict:
        cfg = self.config
        d = self.target_date()
        details = (self.result.get("groundDetails") or {}).get(pair.get("groundId")) or {}
        gym_id = details.get("gymId") or cfg.get("gym_id")
        gym_name = details.get("gymName") or cfg.get("gym_name") or ""
        ground_name = details.get("name") or pair.get("groundName") or ""
        ground_type = str(details.get("groundType") or "0")
        # 与官网一致：getHourMinute() 返回 "HH:mm:00"（带秒，服务器要求 LocalDateTime 格式）
        now_hm = datetime.now().strftime("%H:%M:00")
        start, end = pair.get("start"), pair.get("end")
        order_date = f"{d} {now_hm}"
        st, et = f"{d} {start}:00", f"{d} {end}:00"
        push_type = str(cfg.get("push_type", "0"))
        user = self.result.get("user") or {}
        return {
            "id": captcha_token,
            "customerId": user.get("id") or cfg.get("userid"),
            "customerName": user.get("name") or user.get("customerName") or "",
            "customerTel": (cfg.get("phone") or "") if push_type == "0" else "",
            "userNum": int(cfg.get("user_num") or 1),
            "customerEmail": cfg.get("email") if push_type == "1" else "",
            "gymId": gym_id,
            "gymName": gym_name,
            "groundId": pair.get("groundId"),
            "groundName": ground_name,
            "groundType": ground_type,
            "messagePushType": push_type,
            "isIllegal": "0",
            "orderDate": order_date,
            "startTime": st,
            "endTime": et,
            "tmpOrderDate": order_date,
            "tmpStartTime": st,
            "tmpEndTime": et,
            "gymType": 2,
            "isOverOneDay": "0",
            "title": "",
        }


# ---- 模块级实现，供类内静态方法调用 ----
def _parse_server_time_impl_impl(data) -> float | None:
    """把 getSysTime 的响应解析成 unix epoch ms。兼容时间戳与多种日期格式。"""
    if data is None:
        return None
    v = data.get("data") if isinstance(data, dict) else data
    if isinstance(v, dict):
        v = v.get("time") or v.get("timestamp") or v.get("sysTime")
    if isinstance(v, (int, float)):
        return float(v if v > 1e11 else v * 1000)
    if isinstance(v, str):
        s = v.strip()
        if s.isdigit():
            n = float(s)
            return n if n > 1e11 else n * 1000
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(s[:len(fmt) + 4].rstrip("."), fmt).timestamp() * 1000
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000
        except ValueError:
            return None
    return None


GrabTask._parse_server_time = staticmethod(_parse_server_time_impl_impl)
