import pickle5 as pickle
import numpy as np
import sys
import mysql
from mysql.connector import Error
try:
            mydb = mysql.connector.connect(host='localhost',
                                                user='root',
                                                password='root')
except Error as e:
    print("Error while connecting to MySQL", e)
TrainingData = []
k = 5

TrainingData =np.zeros(k)#init first row in T

fDict = {}
def split_trace(syscallTrace, splitedSize):
    split = [syscallTrace[x:x+splitedSize] for x in range(0, len(syscallTrace), splitedSize) if len(syscallTrace[x:x+splitedSize]) == splitedSize ]
    return split

i = 0
complete_trace = []
mycursor = mydb.cursor(buffered = True)
mycursor.execute("USE SENSORDB")
mycursor.execute("SELECT DISTINCT PID from TRACES")
PIDS = mycursor.fetchall()
output= []


for PID in PIDS:
    sql = """SELECT SYSCALL FROM TRACES WHERE PID = %s ORDER BY ID """ %(PID)
    mycursor.execute(sql)
    trace = split_trace(list(sum(mycursor.fetchall(), ())),5)
    if len(trace) > 0:
        output.extend(trace)
# T = pickle.load(open("/home/rares/HIDS/Decision Engine/AdaptedTraining.pkl","rb"))
# for fileNo,trace in T:
#     k_trace = split_trace(trace,5)
#     output.extend(k_trace)
print(np.shape(output))

for trace in output:
    if len(trace) > 0 :
        TrainingData = np.vstack([TrainingData, trace])
print(np.shape(TrainingData))

# print(TrainingData[:3])
# print(fDict.items()[:10] )                

# # k_lists=split_trace(complete_trace,k)
# for row in output:
#     TrainingData = np.vstack([TrainingData, row])
#     fDict[enco] = fDict.get(str(list(map(int,row))), 0) + 1

TrainingData = TrainingData[1:]#remove first row of zeros
TrainingData,counts=np.unique(TrainingData, axis=0,return_counts=True)

# TrainingData = TrainingData.astype(int)
# counts = counts.astype(int)
# for i in range(0,len(counts)):
#     TrainingData[i] = TrainingData[i] * counts[i]
# print(np.shape(TrainingData))    


pickle.dump(TrainingData, open("/home/rares/HIDS/Decision Engine/remadeLocal.pkl", "wb"))
