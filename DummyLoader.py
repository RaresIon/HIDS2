import mysql.connector
from mysql.connector import Error
global mydb
try:
    mydb = mysql.connector.connect(host='localhost',
                                         user='root',
                                         password='root')
except Error as e:
    print("Error while connecting to MySQL", e)
mydb.autocommit = False

mycursor = mydb.cursor(buffered = True)
mycursor.execute("USE SENSORDB")
# pid_list = mycursor.execute("SELECT DISTINCT PID from TRACES")
# print(pid_list)
mycursor.execute("SELECT DISTINCT PID from TRACES")
PIDS = mycursor.fetchall()
print(type(PIDS))
print(PIDS)
output = []
for PID in PIDS:
    sql = """SELECT SYSCALL FROM TRACES WHERE PID = %s ORDER BY ID LIMIT %s """ %(PID[0], 50)
    mycursor.execute(sql)
    output.append(tuple( (PID[0], list(sum(mycursor.fetchall(), ())))))
for i in output:    
    print(i[0]," has trace -----> ",i[1])
if mydb.is_connected():
    mydb.close()
    mydb.close()
    print("MySQL connection is closed")     