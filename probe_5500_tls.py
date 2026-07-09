#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import socket
import ssl
import json
import time
import sys

TARGET_IP   = "192.168.120.254"
TARGET_PORT = 5500
CONNECT_TIMEOUT = 5      # TCP+TLS 핸드셰이크
READ_TIMEOUT    = 4      # application 응답 대기
SERVER_FIRST_WAIT = 3    # 연결 직후 서버가 먼저 보내는지 대기(초)


def make_ctx():
    """무단 클라이언트 컨텍스트: 인증서 검증 안 함(자체서명 스텁 수용).
    이것 자체가 '기기 신원 검증 불가' 상태를 재현하는 것이며,
    실제 앱이 검증을 하는지는 별도 시험 항목이다."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # 캡처에서 서버가 고른 cipher(0xC028)를 우선 협상하도록 유도
    try:
        ctx.set_ciphers("ECDHE-RSA-AES256-SHA384:DEFAULT")
    except ssl.SSLError:
        pass
    # 일부 임베디드 스택은 하위호환이 필요하므로 최소버전만 살짝 낮춤
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    return ctx


def dump_cert(ssock):
    try:
        der = ssock.getpeercert(binary_form=True)
        cert = ssock.getpeercert()
        print(f"    [TLS] version={ssock.version()} cipher={ssock.cipher()}")
        if cert:
            print(f"    [TLS] peer cert subject={cert.get('subject')}")
            print(f"    [TLS] peer cert issuer ={cert.get('issuer')}")
        else:
            # verify_mode=CERT_NONE면 파싱된 dict가 비어있음. DER 길이만 표기.
            print(f"    [TLS] peer cert(DER) {len(der) if der else 0} bytes "
                  f"(검증 비활성 상태라 파싱 dict 없음)")
    except Exception as e:
        print(f"    [TLS] cert dump err: {e}")


def connect_tls():
    """5500에 TLS 세션 성립. 성공 시 (rawsock, ssock) 반환."""
    raw = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=CONNECT_TIMEOUT)
    ctx = make_ctx()
    ssock = ctx.wrap_socket(raw, server_hostname=None)
    return raw, ssock


def recv_some(ssock, timeout=READ_TIMEOUT, maxbytes=2048):
    """application 응답 수신. 없으면 b''."""
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


def classify(resp, err):
    """DUT 반응 분류 -> 판정 힌트."""
    if err:
        if "reset" in err.lower() or "econnreset" in err.lower():
            return "RESET (세션 리셋 - 프레이밍 불일치 또는 방어적 종료)"
        return f"ERR ({err})"
    if resp == b"":
        return "NO-RESP (무응답 유지 - client-first 대기 또는 무시)"
    # 응답 내용 성격
    txt = None
    try:
        txt = resp.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if txt is not None:
        # JSON 응답이면 파싱 성공 = application layer 도달의 강한 신호
        try:
            j = json.loads(txt)
            return f"JSON-RESP (파싱 성공! application 도달) keys={list(j)[:6]}"
        except Exception:
            return f"TEXT-RESP ({len(resp)}B, 비-JSON 텍스트)"
    return f"BIN-RESP ({len(resp)}B 바이너리)"


def show(tag, resp, err):
    verdict = classify(resp, err)
    print(f"    -> {verdict}")
    if resp:
        prev = resp[:64]
        hexs = prev.hex()
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in prev)
        print(f"       hex: {hexs}")
        print(f"       asc: {asc}")


# ---- JSON-over-TLS 프레이밍 후보 ----
# ThinQ 로컬 provisioning은 JSON 페이로드가 관례. 프레이밍 방식이 미상이므로
# 흔한 4가지 프레이밍으로 같은 논리 payload를 감싸서 어느 것에 반응하는지 관측.

def frame_raw(obj):
    """프레이밍 없이 JSON 바이트 그대로."""
    return json.dumps(obj, separators=(",", ":")).encode()

def frame_newline(obj):
    """개행 종단(line-delimited JSON)."""
    return json.dumps(obj, separators=(",", ":")).encode() + b"\n"

def frame_len_be(obj):
    """4바이트 big-endian 길이 prefix + JSON."""
    body = json.dumps(obj, separators=(",", ":")).encode()
    return len(body).to_bytes(4, "big") + body

def frame_len_le(obj):
    """4바이트 little-endian 길이 prefix + JSON."""
    body = json.dumps(obj, separators=(",", ":")).encode()
    return len(body).to_bytes(4, "little") + body


# 논리 payload 후보들: provisioning 문맥에서 흔한 discovery/info 요청.
# 목적은 '수락'이 아니라 '반응 유발'이다. 무해한 조회성 요청 위주.
PAYLOADS = [
    {"type": "request", "cmd": "getDeviceInfo"},
    {"type": "request", "cmd": "getInfo"},
    {"cmd": "deviceInfo"},
    {"type": "GET", "path": "/device/info"},
    {"request": {"command": "getDeviceInfo"}},
    {"msgType": "request", "cmd": "info"},
]

FRAMINGS = [
    ("raw-json",     frame_raw),
    ("newline-json", frame_newline),
    ("len4be-json",  frame_len_be),
    ("len4le-json",  frame_len_le),
]


def run_matrix():
    print("=" * 68)
    print(f" 5500 JSON-over-TLS application-layer 프로브")
    print(f" target: {TARGET_IP}:{TARGET_PORT}  (노트북 STA -> DUT AP)")
    print("=" * 68)

    # STEP 0: server-first 확인 - 연결만 하고 서버가 먼저 보내는지
    print("\n[STEP 0] TLS 연결 성립 + server-first 관찰")
    try:
        raw, ssock = connect_tls()
    except Exception as e:
        print(f"  [FATAL] TLS 연결 실패: {e}")
        print("  -> 5500이 닫혔거나 TLS 파라미터 불일치. AP 접속/IP 확인.")
        return
    dump_cert(ssock)
    resp, err = recv_some(ssock, timeout=SERVER_FIRST_WAIT)
    if resp:
        print("  [!] 서버가 먼저 데이터 전송 (server-first 프로토콜 신호)")
        show("server-first", resp, err)
    else:
        print("  서버 무송신 -> client-first. 클라이언트가 먼저 보내야 함.")
    try:
        ssock.close()
    except Exception:
        pass

    # STEP 1: 프레이밍 x payload 매트릭스
    print("\n[STEP 1] 프레이밍 × payload 매트릭스 프로브")
    print("(각 시도마다 새 TLS 세션. DUT 반응을 분류)")

    results = []
    for fname, ffunc in FRAMINGS:
        for pl in PAYLOADS:
            label = f"{fname} :: {pl.get('cmd') or pl.get('path') or list(pl.values())[0]}"
            print(f"\n  [{label}]")
            try:
                raw, ssock = connect_tls()
            except Exception as e:
                print(f"    conn-err: {e}")
                results.append((label, f"CONN-ERR:{e}"))
                continue
            try:
                data = ffunc(pl)
                ssock.sendall(data)
                resp, err = recv_some(ssock)
                show(label, resp, err)
                results.append((label, classify(resp, err)))
            except Exception as e:
                print(f"    send/recv-err: {e}")
                results.append((label, f"IO-ERR:{e}"))
            finally:
                try:
                    ssock.close()
                except Exception:
                    pass
            time.sleep(0.3)  # DUT 부담 완화

    # 요약
    print("\n" + "=" * 68)
    print(" 요약 (반응이 있었던 조합만 주목)")
    print("=" * 68)
    hit = False
    for label, verdict in results:
        flag = ""
        if verdict.startswith(("JSON-RESP", "TEXT-RESP", "BIN-RESP")):
            flag = "  <== 반응!"
            hit = True
        print(f"  {label:42s} : {verdict}{flag}")
    print()
    if hit:
        print("[판정 힌트] 응답이 나온 프레이밍이 실제 5500 application 프로토콜의")
        print("            강한 후보. 그 프레이밍으로 정상 명령 스키마 역산 진행.")
        print("            무단 클라이언트가 인증 없이 application에 도달 = AUM/SCM 결함 후보.")
    else:
        print("[판정 힌트] 모든 JSON 프레이밍 무응답/거부. 가능성:")
        print("  (a) client-first 바이너리 커스텀 프레이밍(idx4의 80 00 00 28..). ")
        print("  (b) TLS 세션 성립 후 추가 인증 핸드셰이크 요구(앱 전용 시퀀스).")
        print("  (c) 정상 앱 평문 캡처가 없으면 유효 명령 재현 불가 -> MITM 캡처 필요.")
    print()
    print("주의: 유효 provisioning 명령은 정상 앱 트래픽 평문 없이 만들 수 없음.")
    print("      본 스크립트는 반응 관측/도달성 측정용이며, 그 결과가 findings 근거임.")


if __name__ == "__main__":
    try:
        run_matrix()
    except KeyboardInterrupt:
        print("\n중단됨.")
        sys.exit(1)
