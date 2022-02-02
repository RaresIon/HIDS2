import sys
import glob
import errno
import numpy as np
import pickle5 as pickle
k = 5
T =np.zeros(k)#init first row in T
print(np.shape(T))
fDict = {}
def split_trace(syscallTrace, splitedSize):
    split = [ list(map(int,syscallTrace[x:x+splitedSize])) for x in range(0, len(syscallTrace), splitedSize) if len(syscallTrace[x:x+splitedSize]) == splitedSize ]
    return split

path = '/home/rares/Desktop/ADFA-LD/Training_Data_Master/*.txt'
files = glob.glob(path)
i = 0
BREAK_POINT = 2#max is 833
noSyscalls = 0
complete_trace = []
#read all system callsin a list
for name in files:
    with open(name) as filename:
        trace_of_file = filename.read().split()
        for i in trace_of_file:
            complete_trace.append(i)
k_lists=split_trace(complete_trace,k)
for row in k_lists:
    T = np.vstack([T, row])
    fDict[str(row)] = fDict.get(str(row), 0) + 1
print(T)    





pickle.dump(T, open("/home/rares/featureMatrix.pkl", "wb"))
pickle.dump(fDict, open("/home/rares/freqDict.pkl", "wb"))
        




    
