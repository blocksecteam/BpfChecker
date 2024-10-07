# Make sure you have build the necesary part using build.sh


GENERATOR_PATH=./build/generator/generator
RUNNER_PATH=./rbpf_runner/target/release/rbpf_runne
python3 evaluation/run_wrapper.py --generator ${GENERATOR_PATH} --runner ${RUNNER_PATH} --output output