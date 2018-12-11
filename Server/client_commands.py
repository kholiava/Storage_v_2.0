import sqlite3
import os

with open('server.conf', 'r') as f:
    config = f.readlines()
    FILE_DB = config[4].split('=')[1].strip()
    STORAGE_PATH = config[5].split('=')[1].strip()


def connect(username, password):
    # відкриваємо базу данних
    conn_db = sqlite3.connect(FILE_DB)
    cursor = conn_db.cursor()
    # формуємо sql-запит
    sql_query = """
                    SELECT password
                    FROM user
                    WHERE username=:username           
                    """
    dict_sql = {
        'username': username
    }
    #  отримуємо пароль користувача
    try:
        answer = cursor.execute(sql_query, dict_sql)
    except sqlite3.DatabaseError as err:
        answer = 'Error: ' + str(err)
    else:
        answer = (answer.fetchone())
        #  якщо такого користувача не існує - повертаємо "No such user"
        if answer is None:
            answer = 'Error: no such user.'
        # інакше повертаємо пароль із кортежа
        else:
            answer  = answer[0]
    finally:
        conn_db.close()
    return answer
