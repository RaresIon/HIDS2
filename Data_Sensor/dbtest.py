import mysql.connector
from mysql.connector import Error

try:
    mydb = mysql.connector.connect(host='localhost',
                                         user='root',
                                         password='root')
    print(mydb)                                     
    if mydb.is_connected():
        
        mycursor = mydb.cursor(buffered = True)

        mycursor.execute("SHOW DATABASES")
        mycursor.execute("CREATE DATABASE IF NOT EXISTS Sequences2")
        mycursor.execute("USE Sequences2")
        mycursor.execute("CREATE TABLE IF NOT EXISTS syscalls (id INT AUTO_INCREMENT PRIMARY KEY,TIMESTAMP INT, PID SMALLINT, COMMAND VARCHAR(255), syscall_name VARCHAR(255))")
        mycursor.execute("SHOW TABLES")
        for (table_name,) in mycursor:
            print(table_name)
        mycursor.execute("SELECT * FROM syscalls")
        for i in mycursor.fetchall():
            print(i)    
       


        mycursor.execute("""INSERT INTO 
                   syscalls 
                   (PID, syscall_name) 
               VALUES
                   (%(PID)s, %(syscall_name)s)""", 
            { 
             'PID': '1', 
             'syscall_name': 'mmap'  }) 

except Error as e:
    print("Error while connecting to MySQL", e)
finally:
    if mydb.is_connected():
        mydb.close()
        mydb.close()
        print("MySQL connection is closed")