#! /usr/bin/python3
import os
import glob
from pathlib import Path

# Calculate the correct rate of instruction decode & verifier check

metric_path = "path/to/the/metric/data"
assert os.path.isdir(metric_path)

files = list(Path(metric_path).glob("*"))

class Metric:
    def __init__(self):
        self.total_cnt = 0
        self.instruction_error_cnt = 0
        self.verifier_error_cnt = 0

    def add_data(self, content):
        assert content in ['0','1','2'], "Unkonwn metric data"
        flag = int(content)
        if 0 == flag:
            self.instruction_error_cnt += 1
        elif 1 == flag:
            self.verifier_error_cnt += 1
        else:
            assert flag == 2
        self.total_cnt += 1

    def calc_rate_template(self, factor):
        return f"{round(factor/self.total_cnt,2)*100} ({factor}/{self.total_cnt})"

    def dump(self):
        print(f"Instruction Decode Error: {self.calc_rate_template(self.instruction_error_cnt)}")
        print(f"Verifier Error: {self.calc_rate_template(self.verifier_error_cnt)}")


print(f"calculating with {len(files)} metric data files.")

metric = Metric()

for file in files:
    metric.add_data(open(file).read())

metric.dump()