from sklearn.svm import OneClassSVM
import pickle5 as  pickle
import numpy as np
import glob



def split_trace(syscallTrace, splitedSize):
    split = [ list(map(int,syscallTrace[x:x+splitedSize])) for x in range(0, len(syscallTrace), splitedSize) if len(syscallTrace[x:x+splitedSize]) == splitedSize ]
    return split

T = pickle.load(open("/home/rares/HIDS/Decision Engine/fT.pkl","rb"))    
DE = OneClassSVM(kernel="linear",coef0=0.0,degree=3,nu=0.5,gamma=0.2).fit(T)
f = open("/home/rares/HIDS/Decision Engine/params.txt",'a')
for a in np.arange(0.0, 1.0, 0.05):
    ANOMALY_TRESHOLD = a
    FPR = 0
    i = 0
    ACC = 0
    path = '/home/rares/Desktop/ADFA-LD/Validation_Data_Master/*.txt'
    files = glob.glob(path)
    for name in files:
        with open(name) as filename:
            systemCallTrace = filename.read().split()
            X = split_trace(systemCallTrace, 5)
            print(X)
            decision = DE.predict(X)
            print(len(decision))
            anomalies = np.count_nonzero(decision == 1)
            rate = anomalies/len(decision)
            if rate >= ANOMALY_TRESHOLD:
                FPR = FPR + 1
            i = i+1

    string = 'Treshold parameter is '+str(round(ANOMALY_TRESHOLD,2) ) 
    f.write(string)
    string = ' FPR is '+str(round(FPR/i,2) )         
    f.write(string)        


    path = '/home/rares/Desktop/ADFA-LD/Attack_Data_Master/*/*.txt'
    files = glob.glob(path)
    ACC = 0
    i = 0
    for name in files:
        with open(name) as filename:
            systemCallTrace = filename.read().split()
            X = split_trace(systemCallTrace, 5)
            decision = DE.predict(X)
            anomalies = np.count_nonzero(decision == 1)
            rate = anomalies/len(decision)
            if rate >= ANOMALY_TRESHOLD:
                ACC = ACC + 1              
            i = i+1
    string = ' ACC IS '+str(round(ACC/i,2) )
    f.write(string)
    f.write("\n")
