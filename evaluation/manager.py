import subprocess
import os
import shutil
from datetime import datetime
import argparse

def run_fuzzing(genreator_path, rbpf_runner_path, output_base_path, loop_index) -> bool:
    start_time = datetime.now()
    output_dir = os.path.join(output_base_path, f"output_{datetime.now().strftime('%Y%m%d%H%M%S')}_{loop_index}")
    generator_command = ["./generator", "-o", output_dir, "-n", "100"]
    runner_command = ["./rbpf_runner", "--mode", "batch", output_dir, "--only_vm"]

    # Generate corpus
    subprocess.run(generator_command, check=True)

    # Feed the corpus to rbpf_runner
    runner_process = subprocess.Popen(runner_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = runner_process.communicate()

    if "Differential memory input space found!" in stdout or "Differential memory heap space found!" in stdout or runner_process.returncode != 0:
        print("Issue detected: Differential results.")
        print("Stdout:", stdout)
        print("Stderr:", stderr)
        return True
    else:
        shutil.rmtree(output_dir)
    
    elapsed_time = datetime.now() - start_time
    print(f"[-] Fuzzing iteration {loop_index} completed in {elapsed_time.total_seconds()} seconds.")
    return False


def parse_arguments():
    parser = argparse.ArgumentParser(description="Run fuzzing with custom paths and output directory.")
    parser.add_argument("--output", type=str, required=True, help="The directory to store output files.")
    parser.add_argument("--generator", type=str, default="./generator", help="Path to the generator executable.")
    parser.add_argument("--runner", type=str, default="./rbpf_runner", help="Path to the rbpf_runner executable.")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    output_dir = args.output
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    assert os.path.exists(args.generator)
    assert os.path.exists(args.runner)

    lop_times = 0
    try:
        while True:
            if run_fuzzing(args.generator, args.runner, output_dir, lop_times):
                print("[+] stop when flaws are found.")
                break
            lop_times += 1
    except KeyboardInterrupt:
        print("Fuzzing interrupted by user.")

