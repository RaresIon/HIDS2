from numpy import random
def anomaly_generator():
    comms = ["malware1","malware2","malware3","malware4","malware5"]
    PID = random.randint(40000)
    comm = comms[random.randint(len(comms))]
    return(PID,comm)
ANOMALIES= []

for i in range(0,8):
    ANOMALIES.append(anomaly_generator())
print(ANOMALIES)