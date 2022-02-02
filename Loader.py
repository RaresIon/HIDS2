import mysql.connector
from mysql.connector import Error
import time
def split_trace(syscallTrace, splitedSize):
    split = [ syscallTrace[x:x+splitedSize] for x in range(0, len(syscallTrace), splitedSize) if len(syscallTrace[x:x+splitedSize]) == splitedSize ]
    return split

def run(no_syscalls_per_process):
     try:
            mydb = mysql.connector.connect(host='localhost',
                                                user='root',
                                                password='root')
     except Error as e:
        print("Error while connecting to MySQL", e)
      

     mydb.autocommit = False
     mycursor = mydb.cursor(buffered = True)
     mycursor.execute("USE SENSORDB")
     mycursor.execute("SELECT COUNT(*) from TRACES")             
     res = mycursor.fetchone()
     total_rows = res[0] 
     mydb.close()

     print("waiting for data")
     while total_rows == 0:
          mydb = mysql.connector.connect(host='localhost',user='root',password='root')
          mydb.autocommit = False
          mycursor = mydb.cursor(buffered = True)
          mycursor.execute("USE SENSORDB")
          mycursor.execute("SELECT COUNT(*) from TRACES")             
          res = mycursor.fetchone()
          total_rows = res[0] 
          mydb.close()
          time.sleep(1)


     mydb = mysql.connector.connect(host='localhost',user='root',password='root')
     mydb.autocommit = False
     mycursor = mydb.cursor(buffered = True)
     mycursor.execute("USE SENSORDB")
     mycursor.execute("SELECT DISTINCT PID from TRACES")
     PIDS = mycursor.fetchall()
     output = []
     for PID in PIDS:
          sql = """SELECT SYSCALL FROM TRACES WHERE PID = %s ORDER BY ID LIMIT %s """ %(PID[0], no_syscalls_per_process)
          mycursor.execute(sql)
          strace = split_trace(list(sum(mycursor.fetchall(), ())),5)
          if len(strace) > 0 :
               output.append(tuple( (PID[0], strace )))
     if mydb.is_connected():
            mydb.close()
            mydb.close()
            print("MySQL connection is closed in loader")  
     return output