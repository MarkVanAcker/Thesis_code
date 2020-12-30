import random
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import subprocess
import re
import statistics

#benchmarks to run
#benchmarks2 = ["f64", "fac", "loop", "conversions", "call_indirect"]

benchmarks = ["deepov","2mm"]

ITERATIONS = 10

#get the wasmi results
wasmi = []

for benchmark in benchmarks:

    print("starting "+benchmark+"...")

    times = []
    for i in range(ITERATIONS):
        op = subprocess.check_output(["./target/release/examples/bench", benchmark], cwd="/home/mark/Documents/thesis-bench/wasmi")
        time = int(re.findall(r'\d+', op.decode("utf-8"))[0])
        times.append(time)
    f = open("wasmi_"+benchmark+".txt", 'w')
    for t in times:
        f.write(str(t)+"\n")
    m = statistics.mean(times)
    f.write(str(m))
    wasmi.append(m)
    f.close()


#get the wasmi_sgx results
wasmi_sgx = []

for benchmark in benchmarks:

    print("starting "+benchmark+"...")

    times = []
    for i in range(ITERATIONS):
        op = subprocess.check_output(["./app", "/home/mark/Documents/thesis-bench/thesisbenchmark/"+benchmark+".wast"], cwd="/home/mark/Documents/thesis-bench/incubator-teaclave-sgx-sdk/samplecode/wasmi/bin")
        
        rcved_times = re.findall(r'\d+', op.decode("utf-8"))
        with open("enclave_startup.txt", 'a') as f:
            f.write(rcved_times[0]+"\n")
        time = int(rcved_times[1])
        times.append(time)
        
    f = open("wasmi_sgx_"+benchmark+".txt", 'w')
    for t in times:
        f.write(str(t)+"\n")
    m = statistics.mean(times)
    f.write(str(m))
    wasmi_sgx.append(m)
    f.close()


#plotting code

df = pd.DataFrame({'wasmi': wasmi,

                   'wasmi in SGX': wasmi_sgx}, index=benchmarks)

ind = np.arange(5)
bar_width = 0.35

ax = df.plot.bar(rot=0)

ax.set_ylabel('execution time in µs')
ax.set_xticklabels(benchmarks)
ax.legend()

plt.show()
