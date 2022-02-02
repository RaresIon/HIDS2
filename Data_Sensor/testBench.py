import time
import sys
import csv
import mysql.connector
from mysql.connector import Error
import codecs
import numpy as np
VALUES_TO_COMMIT =  [100, 500, 1000, 5000, 10000, 25000, 50000]
#for value in COMMIT_VALUES:
COMMIT_VALUES = 25000
try:
    mydb = mysql.connector.connect(host='localhost',
                                            user='root',
                                            password='root')

        
    failedExeCount = 0
    failedCommitCount = 0
    mycursor = mydb.cursor()
    mycursor.autocomit = False 
    mycursor.execute("CREATE DATABASE IF NOT EXISTS TestBenchDB")
    mycursor.execute("USE TestBenchDB")
    mycursor.execute("CREATE TABLE IF NOT EXISTS syscalls (id INT AUTO_INCREMENT PRIMARY KEY, PID SMALLINT, COMMAND VARCHAR(255), SYSCALL_NAME VARCHAR(255))")
    start = time.time() 
    b = []
    f = [ "0,0.0,gnome-terminal-,32556,read",
        "1,0.001769267,cinnamon,2277,write",
        "2,0.001792912,cinnamon,2277,read",
        "3,0.016292325,irqbalance,1441,read",
        "4,0.016394526,irqbalance,1441,read",
        "5,0.01645565,irqbalance,1441,read",
        "6,0.016507465,irqbalance,1441,read",
        "7,0.016558882,irqbalance,1441,read",
        "8,0.016599512,irqbalance,1441,read",
        "9,0.016645799,irqbalance,1441,read"]
    for i in range(0,100000):
        b.extend(f)
    print(len(b))
    i = 0
    commit_list = []
    sql = """ insert into syscalls(PID, COMMAND, SYSCALL_NAME)values(%s, %s, %s) """
    for a in b:
        print(i)
        data = a.split(",") 
        if len(commit_list) < COMMIT_VALUES:
            # add values to list
            commit_list.append([data[3],data[2],data[4]])
        else:
            # commit the list
            try:
                mycursor.executemany(sql, commit_list)
            except:
                failedExeCount = failedExeCount + 1
                print("insert failed")
                break
            try:
                print("try to commit")
                mydb.commit()
            except:
                print("failed insert")
                failedCommitCount = failedCommitCount + 1
                break
            commit_list= []
        i = i + 1

except Error as e:
    print("Error while connecting to MySQL", e) 
print("--------------------------------------")    
print("cost :{}".format(time.time() - start))
print("commited every :",COMMIT_VALUES,"  inserts")
print("Queries failed : ",failedExeCount)
print("Commits failed : ",failedCommitCount)
   
print()
query = "SELECT COUNT(*) from syscalls" 
mycursor.execute(query)             #execute query separately
res = mycursor.fetchone()
total_rows = res[0] 
print(total_rows)
if mydb.is_connected():
    mydb.close()
    mydb.close()
    print("MySQL connection is closed")
print("---------------------------------------")    