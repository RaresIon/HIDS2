import mysql.connector
from mysql.connector import Error
def run():
    try:
            mydb = mysql.connector.connect(host='localhost',
                                                user='root',
                                                password='root')
    except Error as e:
        print("Error while connecting to MySQL", e)
    
    mydb.autocommit = False
    mycursor = mydb.cursor(buffered = True)
    mycursor.execute("USE SENSORDB")
    mycursor.execute("DELETE FROM TRACES")
    mycursor.execute("SELECT COUNT(*) from TRACES")             
    res = mycursor.fetchone()
    total_rows = res[0] 
    mydb.commit()
    if mydb.is_connected():
            mydb.close()
            mydb.close()
            print("MySQL connection is closed in clearer")