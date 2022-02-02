import mysql
from mysql.connector import Error
try:
            mydb = mysql.connector.connect(host='localhost',
                                                user='root',
                                                password='root')
except Error as e:
    print("Error while connecting to MySQL", e)
      

def split_trace(syscallTrace, splitedSize):
    split = [ syscallTrace[x:x+splitedSize] for x in range(0, len(syscallTrace), splitedSize) if len(syscallTrace[x:x+splitedSize]) == splitedSize ]
    return split

mydb.autocommit = False
mycursor = mydb.cursor(buffered = True)
mycursor.execute("USE SENSORDB")
mycursor.execute("SELECT  DISTINCT(PID) from TRACES LIMIT 100")
PIDS = mycursor.fetchall()
output = []
for i in PIDS:
    output.append(i[0])
print(output)   
for PID in PIDS:
    sql = """SELECT SYSCALL FROM TRACES WHERE PID = %s ORDER BY ID LIMIT %s """ %(PID[0], 100)
    mycursor.execute(sql)
    strace = split_trace(list(sum(mycursor.fetchall(), ())),5)
    if len(strace) > 0 :
            output.append(tuple( (PID[0], strace )))

if mydb.is_connected():
        mydb.close()
        mydb.close()
        print("MySQL connection is closed in loader")  
print(output)