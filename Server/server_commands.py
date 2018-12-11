import sqlite3
import os

with open('server.conf', 'r') as f:
    config = f.readlines()
    FILE_DB = config[4].split('=')[1].strip()
    STORAGE_PATH = config[5].split('=')[1].strip()


def user_add(username, password):
    user_dir = os.path.join(STORAGE_PATH, username)
    # checking: is there user folder
    # if exist return that user with same name already exists
    if os.path.isdir(user_dir):
        answer = 'Error: user with same name already exists.'
        return answer

    conn_db = sqlite3.connect(FILE_DB)
    cursor = conn_db.cursor()
    sql_query = """
                    INSERT INTO user
                    (username, password)
                    VALUES (:username, :password)
                    """
    dict_sql = {
        'username': username,
        'password': password
    }
    try:
        cursor.execute(sql_query, dict_sql)
    except sqlite3.DatabaseError as err:
        answer = 'Error: ' + str(err)
        if 'UNIQUE constraint' in str(err):
            answer = 'Error: user with same name already exists.'
    else:
        conn_db.commit()
        os.mkdir(user_dir)
        answer = 'OK. New user successfully created.'
    finally:
        conn_db.close()
    return answer


def del_user(username):
    user_dir = os.path.join(STORAGE_PATH, username)
    # checking: is there user folder
    # if not exist return that no such user
    if not os.path.isdir(user_dir):
        answer = 'Error: no such user.'
        return answer

    conn_db = sqlite3.connect(FILE_DB)
    cursor = conn_db.cursor()
    sql_query = """
                    DELETE
                    FROM user
                    WHERE username=:username
                    """
    dict_sql = {
        'username': username
    }
    try:
        cursor.execute(sql_query, dict_sql)
    except sqlite3.DatabaseError as err:
        answer = 'Error: ' + str(err)
    else:
        conn_db.commit()
        file_list = list()
        # Remove all user files and directory
        for file in file_list:
            file_location = os.path.join(user_dir, file)
            os.remove(file_location)
        os.rmdir(user_dir)
        answer = 'OK. The user "{user}" successfully deleted.'.format(user=username)
    finally:
        conn_db.close()
    return answer
