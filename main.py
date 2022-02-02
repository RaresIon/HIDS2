import sys
import SensorClass as Sensor
import Loader as Loader
import Clearer as Clearer
from DE import Decision_Engine
import pickle5 as pickle
import os
import signal
import mysql.connector
from mysql.connector import Error
from multiprocessing import Process, Event, Manager, Value
global mydb
import gui as gui
import time
import subprocess




def agent(decision_engine,mydb,ANOMALY_DICT,TOTAL_TRACES_ANALYZED):
    def keyboardInterruptHandler(signal, frame):
        Clearer.run()
        mydb.commit()
        if mydb.is_connected():
            mydb.close()
            mydb.close()
        print("MySQL connection is closed")
        exit(0)
    
    print("create tracing thread")
    signal.signal(signal.SIGINT, keyboardInterruptHandler)
    while True:
        data = Loader.run(500,)
        print("just read data so dont commit")
        TOTAL_TRACES_ANALYZED.value = TOTAL_TRACES_ANALYZED.value + len(data)
        Clearer.run()
        print("cleared old data so commit")
        Anomaly_PIDS = decision_engine.decide(data,0.5)
        for PID in Anomaly_PIDS:
            bashCommand = "ps -p %s -o comm="%PID
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            comm, error = process.communicate()
            comm = comm.decode('utf-8')
            print("comm of anomaly is ", comm)
            if comm != '' :
                ANOMALY_DICT[PID] = ANOMALY_DICT.get(PID, 0) + 1
            else:
                print("comm empty so not appended")    


if __name__ == "__main__":
   

    T_AFDA = pickle.load(open("/home/rares/HIDS/Decision Engine/fT.pkl","rb")) 
    T_LOCAL =  pickle.load(open("/home/rares/HIDS/Decision Engine/AdaptedTraining.pkl","rb")) 
    decision_engine = Decision_Engine()
    decision_engine.train(T_AFDA)
    try:
            mydb = mysql.connector.connect(host='localhost',
                                                user='root',
                                                password='root')
    except Error as e:
        print("Error while connecting to MySQL", e)
        print("connected to db")


    manager = Manager()
    ANOMALY_DICT = manager.dict()
    TOTAL_TRACES_ANALYZED = manager.Value("i",0)
    

    GUI = Process(target=gui.run, args=(ANOMALY_DICT,TOTAL_TRACES_ANALYZED))
    AGENT = Process(target=agent, args=(decision_engine,mydb,ANOMALY_DICT,TOTAL_TRACES_ANALYZED))
    
    GUI.start()
    AGENT.start()
    
    GUI.join()
    AGENT.join()