import pickle5 as  pickle
import numpy as np
import glob
usedSet = [182,306,163,26,124,139,28,117,293,262,4,16,17,69,39,304,97,79,77,78,85,89,114,8,15,168,152,154,153,219,220,252,249,251,158]
path = '/home/rares/Desktop/ADFA-LD/Training_Data_Master/*.txt'
files = glob.glob(path)
ACC = 0
i = 0
removed_syscalls_no = 0
kept_syscalls_no = 0
traces_lost = 0
traces_kept = 0
NEW_DATASET = []
for name in files:
    with open(name) as filename:
        i = i + 1
        trace = filename.read().split()
        trace = list(map(int, trace))
        original_length = len(trace)
        trace = [x for x in trace if x in usedSet]
        removed_syscalls_no = removed_syscalls_no + original_length - len(trace)
        kept_syscalls_no = kept_syscalls_no + len(trace)
        if len(trace) < 10:
            traces_lost = traces_lost + 1
        else:
            NEW_DATASET.append((i,trace))
            traces_kept = traces_kept + 1    
   
print("Syscalls removed ",removed_syscalls_no)
print("Syscalls kept ",kept_syscalls_no)
print("Lost traces ",traces_lost)
print("Kept traces ",traces_kept)

pickle.dump(NEW_DATASET, open("/home/rares/HIDS/Decision Engine/AdaptedAFDATraining.pkl", "wb"))
