#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import socket
import ssl
import json
import time
import sys
import os

TARGET_IP   = "192.168.120.254"
TARGET_PORT = 5500
CONNECT_TIMEOUT = 5
READ_TIMEOUT    = 4
HEALTH_RETRIES  = 3          # 헬스체크 재시도(일시적 실패와 진짜 다운 구분)
HEALTH_BACKOFF  = 2.0        # 재시도 간 대기(초) — 재부팅 시간 흡수
INTER_VECTOR_DELAY = 0.5     # 벡터 간 간격
LOG_PATH = "robustness_5500_log.txt"


# --------------------------------------------------------------------------
# TLS 하부
# --------------------------------------------------------------------------
def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE      # 자체서명 스텁 수용(무단 클라이언트 재현)
    try:
        ctx.set_ciphers("ECDHE-RSA-AES256-SHA384:DEFAULT")
    except ssl.SSLError:
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    return ctx


def connect_tls(timeout=CONNECT_TIMEOUT):
    raw = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=timeout)
    ctx = make_ctx()
    ssock = ctx.wrap_socket(raw, server_hostname=None)
    return raw, ssock


def recv_some(ssock, timeout=READ_TIMEOUT, maxbytes=4096):
    ssock.settimeout(timeout)
    chunks = []
    try:
        while True:
            b = ssock.recv(maxbytes)
            if not b:
                break
            chunks.append(b)
            if len(b) < maxbytes:
                break
    except socket.timeout:
        pass
    except Exception as e:
        return b"", f"recv-err:{e}"
    return b"".join(chunks), None


# --------------------------------------------------------------------------
# 헬스체크 — 벡터 전송 후 DUT가 살아있는지
# --------------------------------------------------------------------------
def health_check():
    """새 TLS 핸드셰이크 성공 여부 + 왕복시간. (alive:bool, rtt:float|None, note:str)"""
    for attempt in range(1, HEALTH_RETRIES + 1):
        t0 = time.time()
        try:
            raw, ssock = connect_tls(timeout=CONNECT_TIMEOUT)
            rtt = time.time() - t0
            ver = ssock.version()
            try:
                ssock.close()
            except Exception:
                pass
            return True, rtt, f"handshake OK ({ver}) attempt {attempt}"
        except Exception as e:
            if attempt < HEALTH_RETRIES:
                time.sleep(HEALTH_BACKOFF)
                continue
            return False, None, f"handshake FAIL x{HEALTH_RETRIES}: {e}"


# --------------------------------------------------------------------------
# 로버스트니스 벡터 정의
# 각 벡터: (id, 분류, 설명, payload_bytes, destructive?)
# payload는 TLS application data로 전송됨(평문 JSON/바이너리를 TLS로 감쌈)
# --------------------------------------------------------------------------
def j(obj):
    return json.dumps(obj, separators=(",", ":")).encode()

def build_vectors():
    V = []

    # --- 그룹 A: JSON 구조 이상 (비파괴) ---
    V.append(("A1", "malformed-json", "깨진 JSON(닫는 괄호 없음)",
              b'{"type":"request","cmd":"getInfo"', False))
    V.append(("A2", "empty", "빈 페이로드", b"", False))
    V.append(("A3", "empty-json", "빈 객체", b"{}", False))
    V.append(("A4", "wrong-type", "타입 오류(cmd 자리에 숫자)",
              j({"type": "request", "cmd": 12345}), False))
    V.append(("A5", "null-fields", "null 필드",
              j({"type": None, "cmd": None}), False))
    V.append(("A6", "deep-nest", "과도한 중첩(깊이 200)",
              ('{"a":' * 200 + '1' + '}' * 200).encode(), False))
    V.append(("A7", "dup-keys", "중복 키",
              b'{"cmd":"a","cmd":"b","cmd":"c"}', False))
    V.append(("A8", "unicode-abuse", "유니코드/이스케이프 남용",
              j({"cmd": "\u0000\uffff\ud800test\n\r\t"}), False))

    # --- 그룹 B: 경계값/범위 (비파괴) ---
    V.append(("B1", "oversize-string", "초과 길이 문자열(64KB)",
              j({"cmd": "x" * 65536}), False))
    V.append(("B2", "oversize-number", "범위 밖 수치",
              j({"cmd": "setTemp", "value": 10**60}), False))
    V.append(("B3", "neg-number", "음수/이상 수치",
              j({"cmd": "setTemp", "value": -999999}), False))
    V.append(("B4", "many-fields", "필드 폭증(5000개)",
              j({f"k{i}": i for i in range(5000)}), False))
    V.append(("B5", "array-flood", "거대 배열(요소 50000)",
              j({"cmd": "batch", "items": list(range(50000))}), False))

    # --- 그룹 C: 프레이밍/프로토콜 위반 (비파괴) ---
    V.append(("C1", "len-prefix-lie-big", "길이 prefix 과대 선언",
              (0x7FFFFFFF).to_bytes(4, "big") + j({"cmd": "x"}), False))
    V.append(("C2", "len-prefix-lie-small", "길이 prefix 과소 선언",
              (1).to_bytes(4, "big") + j({"cmd": "getInfo"}), False))
    V.append(("C3", "binary-garbage", "임의 바이너리 32B",
              os.urandom(32), False))
    V.append(("C4", "custom-frame-mutate",
              "캡처 커스텀프레임(80 00 00 28..) 변조",
              bytes.fromhex("80000028") + os.urandom(36), False))
    V.append(("C5", "partial-then-idle",
              "부분 전송 후 침묵(slowloris형)",
              b'{"cmd":"getInfo"', False))  # 일부러 미완결 후 유지

    # --- 그룹 D: 파괴적 후보 (반드시 마지막, time-boxed) ---
    #  실제로는 '중단 유발 가능성'이 있는 것들. 각 벡터 후 헬스체크로 회복 확인.
    V.append(("D1", "rapid-reconnect", "급속 재연결 폭주(50회)",
              None, True))   # 특수 처리
    V.append(("D2", "max-payload", "최대 페이로드(1MB)",
              j({"cmd": "x", "blob": "A" * (1024 * 1024)}), True))
    V.append(("D3", "null-flood", "널바이트 대량(64KB)",
              b"\x00" * 65536, True))

    return V


# --------------------------------------------------------------------------
# 벡터 실행
# --------------------------------------------------------------------------
def send_vector(vid, payload):
    """단일 TLS 세션으로 payload 전송, 응답 관측. (resp, err, sess_note)"""
    try:
        raw, ssock = connect_tls()
    except Exception as e:
        return b"", f"conn-err:{e}", "no-session"
    try:
        if payload is not None:
            ssock.sendall(payload)
        if vid == "C5":
            # 부분 전송 후 5초 침묵 유지(slowloris형): 세션 점유 관찰
            time.sleep(5)
        resp, err = recv_some(ssock)
        return resp, err, "ok"
    except Exception as e:
        return b"", f"io-err:{e}", "io-fail"
    finally:
        try:
            ssock.close()
        except Exception:
            pass


def run_rapid_reconnect(n=50):
    """D1: 짧은 시간 급속 재연결. 각 연결 즉시 종료. 자원고갈 관찰."""
    ok = 0
    fail = 0
    for i in range(n):
        try:
            raw, ssock = connect_tls(timeout=3)
            ok += 1
            try:
                ssock.close()
            except Exception:
                pass
        except Exception:
            fail += 1
        # 의도적으로 간격 최소화하되 완전 flood는 아님
        time.sleep(0.05)
    return f"reconnect {n}회: 성공 {ok}, 실패 {fail}"


def classify_response(resp, err):
    if err and "conn-err" in err:
        return "CONN-ERR (연결 자체 실패)"
    if err:
        return f"ERR ({err})"
    if resp == b"":
        return "NO-RESP (무응답 — 조용히 무시 가능성)"
    txt = None
    try:
        txt = resp.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if txt:
        try:
            json.loads(txt)
            return f"JSON-RESP ({len(resp)}B — 구조화 응답)"
        except Exception:
            return f"TEXT-RESP ({len(resp)}B)"
    return f"BIN-RESP ({len(resp)}B)"


# --------------------------------------------------------------------------
# 메인
# --------------------------------------------------------------------------
def main():
    log = open(LOG_PATH, "w", encoding="utf-8")
    def out(s=""):
        print(s)
        log.write(s + "\n")
        log.flush()

    out("=" * 70)
    out(" 로버스트니스 시험 — 5500 provisioning")
    out(f" target {TARGET_IP}:{TARGET_PORT}   시각 {time.strftime('%Y-%m-%d %H:%M:%S')}")
    out("=" * 70)

    # 기준선 헬스체크
    out("\n[BASELINE] 시험 전 DUT 상태 확인")
    alive, rtt, note = health_check()
    out(f"  alive={alive} rtt={rtt} :: {note}")
    if not alive:
        out("  [ABORT] 기준선에서 이미 5500 접속 불가. AP 접속/IP 확인 후 재시도.")
        log.close()
        return
    baseline_rtt = rtt

    vectors = build_vectors()
    nondestr = [v for v in vectors if not v[4]]
    destr    = [v for v in vectors if v[4]]

    results = []

    def run_group(title, group):
        out(f"\n{'='*70}\n[{title}]\n{'='*70}")
        for vid, cat, desc, payload, is_d in group:
            out(f"\n  ── {vid} [{cat}] {desc}")
            if vid == "D1":
                note_send = run_rapid_reconnect()
                out(f"     전송: {note_send}")
                resp_class = "N/A (재연결 시험)"
            else:
                psize = len(payload) if payload is not None else 0
                out(f"     전송: {psize}B")
                resp, err, sess = send_vector(vid, payload)
                resp_class = classify_response(resp, err)
                out(f"     반응: {resp_class}")
                if resp:
                    prev = resp[:48]
                    out(f"        hex: {prev.hex()}")
                    out(f"        asc: " +
                        "".join(chr(b) if 32 <= b < 127 else '.' for b in prev))

            # ── 핵심: 벡터 후 헬스체크 ──
            time.sleep(INTER_VECTOR_DELAY)
            h_alive, h_rtt, h_note = health_check()
            verdict = judge(h_alive, h_rtt, baseline_rtt)
            out(f"     헬스체크: alive={h_alive} rtt={h_rtt} -> {verdict}")
            out(f"        ({h_note})")
            results.append((vid, cat, desc, resp_class, h_alive, verdict))

            if not h_alive:
                out(f"     [!!] DUT 응답 없음 — 복구 대기 후 재확인")
                time.sleep(5)
                r2_alive, r2_rtt, r2_note = health_check()
                out(f"        재확인: alive={r2_alive} ({r2_note})")
                if not r2_alive:
                    out(f"     [FAIL-CONFIRMED] {vid} 이후 5500 서비스 다운 지속.")
                    out(f"        -> 강한 FAIL 증적. 이후 벡터 중단하고 수동 확인 권장.")
                    results[-1] = (vid, cat, desc, resp_class, False,
                                   "FAIL: 서비스 다운 지속")
                    return "halted"
        return "done"

    status = run_group("PHASE 1 — 비파괴 벡터 (구조/경계/프레이밍)", nondestr)

    if status == "done":
        out(f"\n{'#'*70}")
        out("# PHASE 2 — 파괴적 후보 벡터 (time-boxed, 마지막 실행)")
        out("# 각 벡터 후 헬스체크로 회복 확인. 다운 지속 시 자동 중단.")
        out(f"{'#'*70}")
        run_group("PHASE 2 — 파괴적 후보", destr)
    else:
        out("\n[SKIP] Phase 1에서 서비스 다운 감지 — 파괴적 벡터는 실행하지 않음.")

    # 요약 표
    out(f"\n{'='*70}\n 요약\n{'='*70}")
    out(f"  {'ID':4} {'분류':20} {'DUT반응':22} {'판정'}")
    out("  " + "-" * 64)
    fails = []
    for vid, cat, desc, rclass, alive, verdict in results:
        mark = "OK " if verdict.startswith("PASS") else "!! "
        out(f"  {mark}{vid:4} {cat:20} {rclass:22} {verdict}")
        if not verdict.startswith("PASS"):
            fails.append((vid, cat, desc, verdict))

    out("")
    if fails:
        out("  [주의] 통제 미흡(FAIL) 후보:")
        for vid, cat, desc, verdict in fails:
            out(f"    - {vid} {cat}: {desc} -> {verdict}")
        out("")
        out("  이 FAIL 후보들은 워크북에 'DUT가 이상입력에 견고하지 못함'")
        out("  (입력검증 결함, SCM-1/AUM Sufficiency)로 기록 가능한 증적입니다.")
    else:
        out("  모든 벡터에서 DUT 서비스 정상 유지 = 입력검증 견고(PASS 방향).")
        out("  이 경우 '이상입력에 견고하다'는 것도 그 자체로 기록할 결과입니다.")

    out(f"\n로그 저장: {LOG_PATH}")
    log.close()


def judge(alive, rtt, baseline_rtt):
    """헬스체크 결과 -> 판정."""
    if not alive:
        return "FAIL-후보: 벡터 후 5500 접속 불가"
    if rtt is not None and baseline_rtt is not None:
        if rtt > baseline_rtt * 5 and rtt > 2.0:
            return "WARN: 응답 현저 지연(회복은 됨)"
    return "PASS: 서비스 정상 유지"


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n중단됨.")
        sys.exit(1)
