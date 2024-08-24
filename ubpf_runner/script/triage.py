#! /usr/bin/python3
import subprocess
import os
import sys
from multiprocessing import Pool, TimeoutError

fuzzer_path = "/path/to/ubpf_runner/build_fuzzer/prevail_fuzzer"

crash_dir = "/path/to/ubpf_runner/build_fuzzer/crashes"

def triage_once(crash_path:str):
    r = subprocess.run(f"{fuzzer_path} {crash_path}", shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stderr_content = r.stderr.decode()
    summary = " ".join([line for line in stderr_content.splitlines() if "==ERROR:" in line]).strip()
    if summary == "" or "SEGV on unknown address" in summary:
        return
    print(f"{crash_path} : {summary}", flush=True)


with Pool(processes=32) as pool:
    task_lists= []
    for filename in os.listdir(crash_dir):
        if not filename.startswith("crash"):
            continue
        crash_path = os.path.join(crash_dir, filename)
        task_lists.append(pool.apply_async(triage_once, (crash_path,)))

    for index, res in enumerate(task_lists):
        print(f"[{index}/{len(task_lists)}]")
        res.get()
