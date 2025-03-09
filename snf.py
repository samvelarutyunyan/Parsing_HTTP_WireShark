# нужно скачать Npcap
import pymysql.cursors
from scapy.all import *
from urllib.parse import urlparse

from scapy.layers.inet import TCP, IP
from datetime import datetime

dbname = str(input("Введите имя базы данных, которая уже существует: "))
dbtable = str(input("Введите имя таблицы: "))


def connect():
    connection = pymysql.connect(host='127.0.0.1',
                                 user='root',
                                 password='qwerty123',
                                 charset='utf8mb4',
                                 db=dbname,
                                 cursorclass=pymysql.cursors.DictCursor)
    return connection


def create_table():
    global dbtable
    global dbname
    connection = connect()
    with connection.cursor() as cursor:
        sql1 = f"""CREATE TABLE IF NOT EXISTS {dbtable}(Source_IP varchar(255), URL varchar(255), Host_name varchar(255), Start_time datetime);"""
        cursor.execute(sql1)
        connection.commit()
        sql2 = "SHOW TABLES"
        cursor.execute(sql2)
        connection.commit()
        connection.close()
    return


def mysql_input(data):
    global dbtable
    global dbname
    connection = connect()
    print("Подключение к MySQL прошло успешно")
    with connection.cursor() as cursor:
        Source_IP, URL, Host_name, Start_time = data
        sql = f"INSERT INTO {dbtable} (Source_IP, URL, Host_name, Start_time) VALUES(%s, %s, %s, %s)"
        cursor.execute(sql, (Source_IP, URL, Host_name, Start_time))
        connection.commit()
        connection.close()
        print("Данные внесены успешно!")
    return


def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80:
        raw = packet[Raw].load.decode('utf-8', 'ignore')
        try:
            url = urlparse(raw.split('\n')[0].split()[1])
            host = re.findall(r'Referer: (.*?)\r\n', raw)[0]
            now = datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            data = [packet[IP].src, url.path, host, current_time]
            print(f"\nSource IP: {packet[IP].src} URL: {url.netloc}{url.path}")
            print(host)
            print(current_time)
            mysql_input(data)
        except Exception as e:
            pass


if __name__ == '__main__':
    create_table()
    sniff(prn=packet_callback, filter="tcp port 80", store=0)


















