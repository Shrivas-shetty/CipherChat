import argparse
import asyncio
import getpass
import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from app.bench.client import BenchUser
from app.bench.runner import _one_sample


async def run(args):
    pa=os.getenv("CC_BENCH_PASS_A") or getpass.getpass("Password for user A: "); pb=os.getenv("CC_BENCH_PASS_B") or getpass.getpass("Password for user B: ")
    a,b=BenchUser(args.server,args.user_a,pa),BenchUser(args.server,args.user_b,pb); start=datetime.now(timezone.utc); wall_start=datetime.now().astimezone().isoformat()
    try:
        for c in (a,b): await c.ensure_registered(); await c.login()
        await a.connect_ws(); await asyncio.sleep(.1); await b.connect_ws(); ka,kb=await asyncio.gather(a.established(),b.established())
        for i in range(args.messages):
            sender,receiver=(a,b) if i%2==0 else (b,a); sk,rk=(ka,kb) if sender is a else (kb,ka)
            await _one_sample(sender,receiver,sk,rk,"text",120,args.mode,i,marker=f"{args.marker} {i}"); await asyncio.sleep(args.pause_ms/1000)
        if args.with_images:
            for i,side in enumerate((32,64,128),start=args.messages):
                sender,receiver=(a,b) if i%2==0 else (b,a); sk,rk=(ka,kb) if sender is a else (kb,ka)
                await _one_sample(sender,receiver,sk,rk,"image",side,args.mode,i); await asyncio.sleep(args.pause_ms/1000)
        ended=datetime.now(timezone.utc); wall_end=datetime.now().astimezone().isoformat()
        data={"mode":args.mode,"marker":args.marker,"messages":args.messages,"with_images":args.with_images,"server":args.server,"started_at_utc":start.isoformat().replace("+00:00","Z"),"ended_at_utc":ended.isoformat().replace("+00:00","Z"),"local_start":wall_start,"local_end":wall_end,"client_host_ip_if_known":socket.gethostbyname(socket.gethostname()),"pause_ms":args.pause_ms}
        out=Path(__file__).resolve().parents[2]/"data"/"bench"; out.mkdir(parents=True,exist_ok=True); path=out/f"traffic_{args.mode}_{args.label}_{ended.strftime('%Y%m%dT%H%M%SZ')}.json"; path.write_text(json.dumps(data,indent=2),encoding="utf-8"); print(path)
    finally: await asyncio.gather(a.logout(),b.logout(),return_exceptions=True)


def main():
    p=argparse.ArgumentParser(); p.add_argument("--server",required=True); p.add_argument("--mode",choices=("secure","plain"),required=True); p.add_argument("--messages",type=int,default=20); p.add_argument("--marker",default="SECRETWORD123"); p.add_argument("--pause-ms",type=int,default=300); p.add_argument("--with-images",action="store_true"); p.add_argument("--user-a",default="bench_a"); p.add_argument("--user-b",default="bench_b"); p.add_argument("--label",default="traffic"); args=p.parse_args(); print("Start your Wireshark capture BEFORE running this command and stop it after it finishes."); asyncio.run(run(args))


if __name__=="__main__": main()
