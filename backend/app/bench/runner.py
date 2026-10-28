import asyncio
import base64
import json
import math
import re
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from app.bench.client import BenchUser
from app.bench.payloads import make_rgb, make_text


def schedule(repeats: int):
    return [("secure", "plain") if i % 2 == 0 else ("plain", "secure") for i in range(repeats)]


async def run_benchmark(server, user_a, user_b, pass_a, pass_b, *, repeats=2, warmup=1,
                        handshakes=2, text_lengths=(16,256), image_sides=(16,64), label="benchmark",
                        note=None, no_post=False, analyst=None, analyst_password=None):
    if repeats < 1 or warmup < 0 or handshakes < 0:
        raise ValueError("repeats must be positive; warmup and handshakes cannot be negative")
    safe = re.compile(r"^[A-Za-z0-9 _.\-]+$")
    if not safe.fullmatch(label) or (note is not None and not safe.fullmatch(note)):
        raise ValueError("label and note may contain only letters, digits, spaces, underscore, dot, and hyphen")
    a,b=BenchUser(server,user_a,pass_a),BenchUser(server,user_b,pass_b)
    samples=[]; handshake_values=[]
    try:
        for client in (a,b): await client.ensure_registered(); await client.login()
        # Record complete handshake repetitions, then make a fresh session for message measurements.
        for _ in range(max(0, handshakes)):
            await a.connect_ws(); await asyncio.sleep(.1); await b.connect_ws()
            keys_a,keys_b=await asyncio.gather(a.established(),b.established())
            handshake_values.append(keys_b.duration_ms)
            await asyncio.gather(a.close(), b.close()); await asyncio.sleep(.15)
        await a.connect_ws(); await asyncio.sleep(.1); await b.connect_ws()
        keys_a,keys_b=await asyncio.gather(a.established(),b.established())
        baseline_enabled=True
        for kind, sizes in (("text",text_lengths),("image",image_sides)):
            for size in sizes:
                if size == min(sizes):
                    for mode in ("secure", "plain"):
                        if mode == "plain" and not baseline_enabled: continue
                        for _ in range(warmup):
                            try: await _one_sample(a,b,keys_a,keys_b,kind,size,mode,-1)
                            except RuntimeError as exc:
                                if mode != "plain" or "ALLOW_PLAINTEXT_BASELINE=true" not in str(exc): raise
                                baseline_enabled=False
                                print("start the server with ALLOW_PLAINTEXT_BASELINE=true to include the baseline")
                for rep, order in enumerate(schedule(repeats)):
                    sender,receiver=(a,b) if rep%2==0 else (b,a)
                    sk,rk=(keys_a,keys_b) if sender is a else (keys_b,keys_a)
                    for mode in order:
                        if mode == "plain" and not baseline_enabled: continue
                        try:
                            samples.append(await _one_sample(sender,receiver,sk,rk,kind,size,mode,len(samples)))
                        except RuntimeError as exc:
                            if mode != "plain" or "ALLOW_PLAINTEXT_BASELINE=true" not in str(exc): raise
                            baseline_enabled=False
                            print("start the server with ALLOW_PLAINTEXT_BASELINE=true to include the baseline")
        run={"label":label,"repeats":repeats,"warmup":warmup,"text_lengths":list(text_lengths),"image_sides":list(image_sides),"handshake_ms":handshake_values,"note":note,"samples":samples}
        local=Path(__file__).resolve().parents[2]/"data"/"bench"; local.mkdir(parents=True,exist_ok=True)
        stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"); path=local/f"{label}_{stamp}.json"; path.write_text(json.dumps(run,indent=2),encoding="utf-8")
        print("mode kind size n mean_ms median_ms p95_ms mean_bytes_up secure_plain_ratio")
        groups={}
        for s in samples: groups.setdefault((s["mode"],s["kind"],s["size_param"]),[]).append(s)
        for key,items in groups.items():
            times=[x["e2e_ms"] for x in items]
            secure_group=groups.get(("secure",key[1],key[2]),[]); plain_group=groups.get(("plain",key[1],key[2]),[])
            plain_mean=statistics.mean([x["e2e_ms"] for x in plain_group]) if plain_group else None
            ratio=(statistics.mean([x["e2e_ms"] for x in secure_group])/plain_mean) if secure_group and plain_mean else None
            p95=sorted(times)[max(0,math.ceil(.95*len(times))-1)]
            print(*key,len(items),round(statistics.mean(times),2),round(statistics.median(times),2),round(p95,2),round(statistics.mean(x["bytes_up"] for x in items),1),round(ratio,3) if ratio is not None else "n/a")
        if not no_post:
            analyst_client=BenchUser(server,analyst,analyst_password); await analyst_client.login()
            try:
                response=await analyst_client.http.post("/api/dashboard/bench/runs",json=run,headers=analyst_client._headers()); response.raise_for_status()
            except Exception as exc:
                print(f"Could not post benchmark results: {exc}. Local JSON is at {path}")
            finally: await analyst_client.logout()
        return {"run":run,"path":str(path)}
    finally: await asyncio.gather(a.logout(),b.logout(),return_exceptions=True)


async def _one_sample(sender,receiver,send_keys,recv_keys,kind,size,mode,seq,marker=None):
    from app.crypto.envelope import verify_and_decrypt
    t0=time.perf_counter()
    text=make_text(size,marker=marker,seed=seq if seq>=0 else 0) if kind=="text" else None
    rgb=make_rgb(size,seed=seq if seq>=0 else 0) if kind=="image" else None
    plaintext=text.encode() if text is not None else rgb
    if mode=="secure":
        from app.crypto.envelope import encrypt_message,image_meta_json
        sender.send_counter+=1; meta=image_meta_json(size,size) if kind=="image" else "{}"
        env=encrypt_message(send_keys.enc,send_keys.mac,send_keys.session_id,send_keys.sender_role,sender.send_counter,plaintext,kind,meta)
        payload={"session_id":send_keys.session_id,"counter":sender.send_counter,"msg_type":kind,"meta_json":meta,"iv":env.iv_b64,"ct":env.ct_b64,"hmac":env.hmac_b64,
                 **sender.signature_fields(env,len(plaintext),send_keys.mac)}
        body=json.dumps(payload,separators=(",",":")).encode()
    elif kind=="text": payload={"text":text}; body=json.dumps({"session_id":send_keys.session_id,"kind":"text",**payload},separators=(",",":")).encode()
    else: payload={"w":size,"h":size,"data_b64":base64.b64encode(rgb).decode()}; body=json.dumps({"session_id":send_keys.session_id,"kind":"image",**payload},separators=(",",":")).encode()
    t1=time.perf_counter()
    if mode=="secure":
        res=await sender.http.post("/api/messages",content=body,headers={**sender._headers(),"Content-Type":"application/json"}); res.raise_for_status(); t2=time.perf_counter(); message_id=res.json()["id"]
    else:
        res=await sender.http.post("/api/baseline/messages",content=body,headers={**sender._headers(),"Content-Type":"application/json"})
        if res.status_code==404: raise RuntimeError("start the server with ALLOW_PLAINTEXT_BASELINE=true to include the baseline")
        res.raise_for_status(); t2=time.perf_counter(); message_id=res.json()["id"]
    (frame,t3,ws_len)=await receiver._wait("message_available" if mode=="secure" else "baseline_available")
    if frame["message_id"]!=message_id: raise RuntimeError("unexpected notification ordering")
    if t3<t1: raise RuntimeError("notification arrived before POST body was ready")
    if mode=="secure":
        response=await receiver.http.get(f"/api/messages/{message_id}",headers=receiver._headers()); response.raise_for_status(); t4=time.perf_counter(); data=response.json()
        from app.crypto.envelope import Envelope, build_mac_input
        import hashlib, hmac
        from app.crypto.sigverify import build_signature_input, verify_ecdsa
        env=Envelope(data["session_id"],data["from_role"],data["counter"],data["msg_type"],data["meta_json"],base64.b64decode(data["iv"]),base64.b64decode(data["ct"]),base64.b64decode(data["hmac"]))
        mac_input=build_mac_input(env.session_id,env.sender_role,env.counter,env.msg_type,env.meta_json,env.iv,env.ct)
        if not hmac.compare_digest(hmac.new(recv_keys.mac,mac_input,hashlib.sha256).digest(),env.hmac): raise RuntimeError("HMAC verification failed")
        public=await receiver.http.get(f"/api/keys/{data['signer_key_id']}",headers=receiver._headers()); public.raise_for_status()
        if public.json()["user_id"]!=data["sender_id"]: raise RuntimeError("signing key identity mismatch")
        sig_start=time.perf_counter(); sig_ok=verify_ecdsa(base64.b64decode(public.json()["public_key_b64"]),base64.b64decode(data["signature"]),build_signature_input(mac_input,env.hmac)); sig_verify_ms=max(0.001,(time.perf_counter()-sig_start)*1000)
        if not sig_ok: raise RuntimeError("signature verification failed")
        role=send_keys.sender_role; receiver.recv_counter=max(receiver.recv_counter,0)
        decoded=verify_and_decrypt(recv_keys.enc,recv_keys.mac,recv_keys.session_id,role,env,receiver.recv_counter); receiver.recv_counter=env.counter
        t5=time.perf_counter(); verify=await receiver.http.post(f"/api/messages/{message_id}/verification",json={"status":"verified","sig_status":"valid","sig_verify_ms":sig_verify_ms},headers=receiver._headers()); verify.raise_for_status(); verify_ms=(time.perf_counter()-t5)*1000
    else:
        response=await receiver.http.get(f"/api/baseline/messages/{message_id}",headers=receiver._headers()); response.raise_for_status(); t4=time.perf_counter(); data=response.json()
        decoded=data["text"].encode() if kind=="text" else base64.b64decode(data["data_b64"]); verify_ms=None; t5=time.perf_counter()
    if decoded!=plaintext: raise RuntimeError("received payload mismatch")
    return {"seq":max(seq,0),"mode":mode,"kind":kind,"size_param":size,"plaintext_bytes":len(plaintext),"crypto_send_ms":(t1-t0)*1000,"to_notify_ms":(t3-t1)*1000,"fetch_ms":(t4-t3)*1000,"crypto_recv_ms":(t5-t4)*1000,"e2e_ms":(t5-t0)*1000,"post_ms":(t2-t1)*1000,"verify_post_ms":verify_ms,"bytes_up":len(body),"bytes_down":len(response.content),"ws_notify_bytes":ws_len}
