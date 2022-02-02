import Trainingsensor as Sensor
from multiprocessing import Manager, Process
import mysql.connector
from mysql.connector import Error
import time
manager = Manager()
try:
    mydb = mysql.connector.connect(host='localhost',
                                                user='root',
                                                password='root')
except Error as e:
    print("Error while connecting to MySQL", e)


mydb.autocommit = False
(bpf) = Sensor.init_probes()
sensor = Process(target=Sensor.gather_data, args=(mydb,bpf))
sensor.daemon = True
sensor.start()
sensor.join()
