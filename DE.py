from sklearn.svm import OneClassSVM
import numpy as np
import logging

class Decision_Engine:

    def __init__(self):
        self.anomalies = 0
        self.notraces = 0
        self.DE = OneClassSVM(kernel="linear",coef0=0.0,degree=3,nu=0.5,gamma=0.2) 
        logging.basicConfig(filename='HIDSLOG.log')

    def train(self, data):
        self.DE.fit(data)
    
    def decide(self, data, TRESHOLD):
        ANOMALIES = []
        print("---------------------number of pids in DE : ",len(data))
        for (pid,traces) in data:
            if len(traces) > 0:
                decision = self.DE.predict(traces)
                anomalies = np.count_nonzero(decision == -1)
                rate = anomalies/len(decision)
                if rate >= TRESHOLD:
                    print("ANOMALY FOUND -----> ",pid)
                    logging.info(("ANOMALY ",str(pid)))
                    ANOMALIES.append(pid)
                    self.anomalies = self.anomalies + 1
                else:
                    # print("NOMRAL ---> ", pid)
                    logging.info(("NORMAL ",str(pid)))
                    self.notraces = self.notraces + 1
        
        print("FPR : ", self.anomalies / (self.notraces + self.anomalies) )
        return ANOMALIES


