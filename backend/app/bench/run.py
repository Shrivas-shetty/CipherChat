import argparse
import asyncio
import getpass
import os

from app.bench.runner import run_benchmark


def csv_int(value): return tuple(int(x) for x in value.split(",") if x)


async def main_async(args):
    if args.quick: args.repeats,args.warmup,args.handshakes,args.text_lengths,args.image_sides=2,1,2,(16,256),(16,64)
    pa=os.getenv("CC_BENCH_PASS_A") or getpass.getpass("Password for user A: ")
    pb=os.getenv("CC_BENCH_PASS_B") or getpass.getpass("Password for user B: ")
    print("For realistic latency, run this command from the OTHER laptop on your Wi-Fi/LAN.")
    if not args.no_post and not args.analyst: raise SystemExit("--analyst is required unless --no-post is used")
    password=os.getenv("CC_BENCH_PASS_ANALYST") or (getpass.getpass("Analyst password: ") if not args.no_post else None)
    return await run_benchmark(args.server,args.user_a,args.user_b,pa,pb,repeats=args.repeats,warmup=args.warmup,handshakes=args.handshakes,text_lengths=args.text_lengths,image_sides=args.image_sides,label=args.label,note=args.note,no_post=args.no_post,analyst=args.analyst,analyst_password=password)


def main():
    p=argparse.ArgumentParser(); p.add_argument("--server",required=True); p.add_argument("--user-a",default="bench_a"); p.add_argument("--user-b",default="bench_b"); p.add_argument("--analyst"); p.add_argument("--repeats",type=int,default=10); p.add_argument("--warmup",type=int,default=2); p.add_argument("--handshakes",type=int,default=10); p.add_argument("--text-lengths",type=csv_int,default=(16,64,256,1024,2000)); p.add_argument("--image-sides",type=csv_int,default=(16,64,128,256,512)); p.add_argument("--label",default="benchmark"); p.add_argument("--note"); p.add_argument("--no-post",action="store_true"); p.add_argument("--quick",action="store_true"); asyncio.run(main_async(p.parse_args()))


if __name__ == "__main__": main()
