# -*- coding: utf-8 -*-
"""tianai-captcha SLIDER 求解器。

协议（经对 reservation.sustech.edu.cn 实测验证）：
  POST /api/blade-base/captcha/generate/d  body {} -> {code, id, captcha:{backgroundImage, templateImage, ...}}
  POST /api/blade-base/captcha/check/d     body {id, data:{bgImageWidth, bgImageHeight, templateImageWidth,
                                            templateImageHeight, startTime, stopTime, trackList}}
  -> {code:200, data:"<verification token>"}；code 4001 = 位置错误；其他 = 验证码已失效。
答案：trackList 最后一项的 x（拖动像素）。若上报 bgImageWidth == 背景图原始宽度，则答案坐标
等于缺口左边缘在原始图中的 x（scale = 1），实测通过。
每个 id 只允许校验一次（失败后再试返回 4000）。
"""
import base64
import io
import random
import time

import numpy as np
from PIL import Image


def decode_dataurl(u: str) -> Image.Image:
    return Image.open(io.BytesIO(base64.b64decode(u.split(",", 1)[1])))


def _sobel(g: np.ndarray) -> np.ndarray:
    gx = np.zeros_like(g)
    gy = np.zeros_like(g)
    gx[:, 1:-1] = g[:, 2:] - g[:, :-2]
    gy[1:-1, :] = g[2:, :] - g[:-2, :]
    return np.sqrt(gx * gx + gy * gy)


def solve_slider(bg_img: Image.Image, tpl_img: Image.Image):
    """返回 (answer_x, meta)。

    answer_x 直接可作为拖动距离上报（背景原始坐标系）。
    依据 dromara/tianai-captcha 生成器源码：整条模板带（含左右透明边距）被贴在
    randomX 处，缺口可见左边缘 = randomX + 剪影在带内的左偏移 x0，
    服务端校验 |answer/宽 - randomX/宽| < 容差(默认2%)，故 answer = 匹配位置 - x0。
    """
    bg = np.asarray(bg_img.convert("RGB"), dtype=np.float32)
    tpl = np.asarray(tpl_img.convert("RGBA"), dtype=np.float32)
    mask = tpl[..., 3] > 150
    ys, xs = np.where(mask)
    y0, y1 = int(ys.min()), int(ys.max()) + 1
    x0, x1 = int(xs.min()), int(xs.max()) + 1
    piece = tpl[y0:y1, x0:x1, :3]          # (ph, pw, 3)
    pmask = mask[y0:y1, x0:x1]
    ph, pw = pmask.shape
    bh, bw = bg.shape[:2]

    pm = pmask.astype(np.float32)
    n = float(pm.sum())
    p_rgb = piece[pmask]                    # (n, 3)
    p_gray = p_rgb.mean(axis=1)

    bg_gray = bg.mean(axis=2)
    p_edge = _sobel(piece.mean(axis=2))
    b_edge = _sobel(bg_gray)

    ring = pmask & ~_erode(pmask.copy(), 3)
    ring_d = ring | np.roll(ring, 1, 0) | np.roll(ring, -1, 0) | np.roll(ring, 1, 1) | np.roll(ring, -1, 1)
    interior = pmask & ~ring_d
    p_int = piece[interior].mean(axis=1)
    p_int_sq = float(np.dot(p_int, p_int)) + 1e-6

    # randomX ∈ [tplW+5, bgW-tplW-10]，可见缺口边缘 = randomX + x0
    tpl_w = tpl.shape[1]
    lo = max(0, tpl_w + 5 - 6 + x0)
    hi = min(bw - pw, bw - tpl_w - 10 + 6 + x0)

    scores = np.full(bw - pw + 1, np.inf, dtype=np.float32)
    for x in range(lo, hi + 1):
        # 1) 缺口白边/光晕 → 轮廓环上的强边缘
        e_ring = float(b_edge[y0:y1, x:x + pw][ring_d].mean())
        # 2) 缺口内部 = 原图内容被压暗：限制比例的线性回归残差
        b_int = bg[y0:y1, x:x + pw][interior].mean(axis=1)
        a = float(np.dot(p_int, b_int)) / p_int_sq
        a_c = min(0.75, max(0.15, a))
        resid = float(np.abs(b_int - a_c * p_int).mean())
        scores[x] = resid - 1.2 * e_ring

    finite = np.where(np.isfinite(scores))[0]
    if len(finite) == 0:
        return 0, {"error": "no candidates"}
    order = finite[np.argsort(scores[finite])]
    best_x = int(order[0])
    smax, smin = float(scores[finite].max()), float(scores[finite].min())
    prominence = (smax - smin) / (smax + 1e-6)

    answer = best_x - x0
    meta = {
        "y": y0, "piece_x_in_tpl": x0, "pw": pw, "ph": ph,
        "match_x": best_x, "prominence": round(prominence, 3),
        "top3": [int(i) for i in order[:3]],
    }
    return answer, meta


def _erode(m: np.ndarray, it: int = 1) -> np.ndarray:
    r = m.copy()
    for _ in range(it):
        r = r & np.roll(r, 1, 0) & np.roll(r, -1, 0) & np.roll(r, 1, 1) & np.roll(r, -1, 1)
    return r


def make_track(ans_x: int, total_ms: int | None = None) -> list:
    """合成拟人拖动轨迹。满足 tianai BasicTrackCaptchaInterceptor：
    时长>300ms、点数>=10、首点在±10内、y 不全相同、无 >50 突跳、后段平均点间隔更大（减速）。"""
    total_ms = total_ms or random.randint(700, 1000)
    pts = [{"x": 0, "y": 0, "type": "down", "t": 0}]
    n = random.randint(18, 26)
    ys = [random.choice([-2, -1, 0, 1, 2]) for _ in range(n + 1)]
    if all(v == 0 for v in ys):        # 保证 y 不全相同（检测4）
        ys[0] = 1
    overshoot = random.choice([0, 0, 0, random.randint(1, 3)])
    for i in range(1, n + 1):
        p = i / n
        ease = 1 - (1 - p) ** 2.4
        x = ans_x * ease + (overshoot if p > 0.75 else 0)
        x += random.uniform(-1.5, 1.5) * (1 - p)
        if i == n:
            x = ans_x + overshoot
        t = int(total_ms * (i / n) ** 1.4)   # 时间指数>1 → 后段点间隔更大（减速）
        pts.append({"x": max(0, round(x)), "y": ys[i], "type": "move", "t": t})
    pts.append({"x": int(ans_x), "y": ys[-1], "type": "up",
                "t": total_ms + random.randint(60, 140)})
    return pts


def build_check_body(captcha_id: str, cap: dict, ans_x: int, *, elapsed_ms: int | None = None) -> dict:
    ow = cap.get("backgroundImageWidth", 600)
    oh = cap.get("backgroundImageHeight", 360)
    tw = cap.get("templateImageWidth", 110)
    th = cap.get("templateImageHeight", 360)
    elapsed_ms = elapsed_ms or random.randint(700, 1100)
    now = int(time.time() * 1000)
    return {
        "id": captcha_id,
        "data": {
            "bgImageWidth": ow, "bgImageHeight": oh,
            "templateImageWidth": tw, "templateImageHeight": th,
            "startTime": now - elapsed_ms - 200, "stopTime": now,
            "trackList": make_track(int(ans_x)),
        },
    }
