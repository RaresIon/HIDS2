from sklearn.svm import OneClassSVM
import pickle5 as  pickle
import numpy as np
import glob



def split_trace(syscallTrace, splitedSize):
    split = [ list(map(int,syscallTrace[x:x+splitedSize])) for x in range(0, len(syscallTrace), splitedSize) if len(syscallTrace[x:x+splitedSize]) == splitedSize ]
    return split

T1 = pickle.load(open("/home/rares/HIDS/Decision Engine/fT.pkl","rb")) 
T2 = pickle.load(open("/home/rares/HIDS/Decision Engine/TrainingAfda.pkl","rb"))
T2 = np.vstack((T2,T1))
print(np.shape(T2))  
DE = OneClassSVM(kernel="linear",coef0=0.0,degree=3,nu=0.5,gamma=0.2).fit(T2)
f = open("/home/rares/HIDS/Decision Engine/params.txt",'a')
for a in np.arange(0.0, 1, 0.1):
    ANOMALY_TRESHOLD = a
    FPR = 0
    ACC = 0

    ValidationData = pickle.load(open("/home/rares/HIDS/Decision Engine/AdaptedValidation.pkl","rb"))
    i = 0
    for (fileNo,trace) in ValidationData:
        X = split_trace(trace, 5)
        decision = DE.predict(X)
        anomalies = np.count_nonzero(decision == -1)
        rate = anomalies/len(decision)
        if rate > ANOMALY_TRESHOLD:
            FPR = FPR + 1              
        i = i+1

    string = 'Treshold parameter is '+str(round(ANOMALY_TRESHOLD,3) ) 
    f.write(string)
    string = ' FPR is '+str(round(FPR/i,2) )         
    f.write(string)        


    AttackData = pickle.load(open("/home/rares/HIDS/Decision Engine/AdaptedAttacks.pkl","rb"))
    ACC = 0
    i = 0
    for (fileNo,trace) in AttackData:
        X = split_trace(trace, 5)
        decision = DE.predict(X)
        anomalies = np.count_nonzero(decision == -1)
        rate = anomalies/len(decision)
        if rate > ANOMALY_TRESHOLD:
            ACC = ACC + 1              
        i = i+1
    string = ' ACC IS '+str(round(ACC/i,2) )
    f.write(string)
    f.write("\n")
