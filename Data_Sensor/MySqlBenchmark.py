import time
import sys
import csv
import mysql.connector
from mysql.connector import Error
import codecs



try:
    mydb = mysql.connector.connect(host='localhost',
                                         user='root',
                                         password='root')


    failedExeCount = 0
    failedCommitCount = 0
    mycursor = mydb.cursor()
    mycursor.autocomit = False
    mycursor.execute("CREATE DATABASE IF NOT EXISTS BenchDB")
    mycursor.execute("USE BenchDB")
    mycursor.execute("CREATE TABLE IF NOT EXISTS syscalls (id INT AUTO_INCREMENT PRIMARY KEY, PID SMALLINT, COMMAND VARCHAR(255), SYSCALL_NAME VARCHAR(255))")

    i = 0
    # with open('benchmarkData.csv', 'r') as file:
    #     reader = csv.reader(file)

    commit_at = [2500, 5000,10000,25000, 50000, 100000]
    com_list = []
    for rows_per_commit in commit_at:
        start = time.time()
        commits = 0
        f = open("benchmarkData.csv","r")
        if True :
            for row in f:
                data = row.split(",")
                i = i +1
                sql = "insert into syscalls(PID, COMMAND, SYSCALL_NAME)values(%s, %s, %s)"
                if i > 1 :
                        if len(data) != 5:
                            print("error reading line")
                        else:
                            try:
                                com_list.append((data[3], data[2], data[4]))
                            except:
                                print("failed insert")
                                failedExeCount = failedExeCount + 1
                                break
                if len(com_list) == rows_per_commit:
                    try:
                        mycursor.executemany(sql,com_list )
                        mydb.commit()
                        commits = commits + 1
                        com_list = []
                    except:
                        failedCommitCount = failedCommitCount + 1
        f.close()
        print(rows_per_commit, " entries per commit")
        print("cost : ",'{0:.10f}'.format(round((time.time() - start),7)))
        print("Queries failed : ",failedExeCount)
        print("Commits made : ",commits)


except Error as e:
    print("Error while connecting to MySQL", e)

if mydb.is_connected():
    mydb.close()
    mydb.close()
    print("MySQL connection is closed")
