from flask import request, Flask, jsonify
import pymongo
from bson.json_util import dumps
import time
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
from Pyfhel import Pyfhel

app = Flask(__name__)

connection_url = 'mongodb://cobadatabase:pwdb@cluster0-shard-00-00.sxr4g.gcp.mongodb.net:27017,cluster0-shard-00-01.sxr4g.gcp.mongodb.net:27017,cluster0-shard-00-02.sxr4g.gcp.mongodb.net:27017/Example?ssl=true&replicaSet=atlas-u07olz-shard-0&authSource=admin&retryWrites=true&w=majority'
client = pymongo.MongoClient(connection_url)

database = client.get_database('Example')
Suhu = database.SuhuWifiLangsung
BB = database.BBWifiLangsung
DJ = database.DJWifiLangsung
User = database.user
credsh = database.credentialsuhu
credbb = database.credentialbb
creddj = database.credentialdj

sharedPrime = 2147483647
sharedGenerator = 16807
sec = 214748363

hashkeysuhu = ''
ivdcdsuhu = ''
hashkeybb = ''
ivdcdbb = ''
hashkeydj = ''
ivdcddj = ''

dataSuhu = []
dataBB = []
dataDJ = []

dataHESuhu = []
dataHEBB = []
dataHEDJ = []

he = Pyfhel()
he.contextGen(p=65537)
he.keyGen()

@app.route('/', methods = ['GET','POST'])
def hello_world():
    return 'Assalamualaikum, ini web server App 1 MBC Laboratory :) Baru'

@app.route('/postkeysuhu', methods = ['POST'])
def postKeySuhu():
    global hashkeysuhu
    global ivdcdsuhu
    key = request.json['pub_key']
    iv = request.json['iv']

    sharedKey = pow(int(key), sec, sharedPrime)
    hashkeysuhu = str(hashlib.sha256(str(sharedKey).encode("utf-8")).hexdigest())
    ivdcdsuhu = hexlify(b64decode(str(iv).encode("utf-8"))).decode("utf-8")

    print("Shared Key : " + str(sharedKey))
    print("Pub Key dari Sensor: " + str(key))
    print("Hash256 Key untuk dekripsi : " + hashkeysuhu)
    print("IV untuk dekripsi: " + ivdcdsuhu)
    return ""

@app.route('/postkeybb', methods = ['POST'])
def postKeyBB():
    global hashkeybb
    global ivdcdbb
    key = request.json['pub_key']
    iv = request.json['iv']

    sharedKey = pow(int(key), sec, sharedPrime)
    hashkeybb = str(hashlib.sha256(str(sharedKey).encode("utf-8")).hexdigest())
    ivdcdbb = hexlify(b64decode(str(iv).encode("utf-8"))).decode("utf-8")

    print("Shared Key : " + str(sharedKey))
    print("Pub Key dari Sensor: " + str(key))
    print("Hash256 Key untuk dekripsi : " + hashkeybb)
    print("IV untuk dekripsi: " + ivdcdbb)
    return ""

@app.route('/postkeydj', methods = ['POST'])
def postKeyDJ():
    global hashkeydj
    global ivdcddj
    key = request.json['pub_key']
    iv = request.json['iv']

    sharedKey = pow(int(key), sec, sharedPrime)
    hashkeydj = str(hashlib.sha256(str(sharedKey).encode("utf-8")).hexdigest())
    ivdcddj = hexlify(b64decode(str(iv).encode("utf-8"))).decode("utf-8")

    print("Shared Key : " + str(sharedKey))
    print("Pub Key dari Sensor: " + str(key))
    print("Hash256 Key untuk dekripsi : " + hashkeydj)
    print("IV untuk dekripsi: " + ivdcddj)
    return ""

@app.route('/pksuhu', methods = ['GET', 'POST'])
def pubkeySuhu():
    B = pow(sharedGenerator, sec, sharedPrime)
    print("Pub Key untuk Sensor : " + str(B))
    return jsonify(B)

@app.route('/pkbb', methods = ['GET', 'POST'])
def pubkeyBB():
    B = pow(sharedGenerator, sec, sharedPrime)
    print("Pub Key untuk Sensor : " + str(B))
    return jsonify(B)

@app.route('/pkdj', methods = ['GET', 'POST'])
def pubkeyDJ():
    B = pow(sharedGenerator, sec, sharedPrime)
    print("Pub Key untuk Sensor : " + str(B))
    return jsonify(B)

@app.route("/info/suhu", methods = ['GET','POST'])
def get_all_suhu():
    datasuhu = Suhu.find()
    output = []
    for s in datasuhu:
        output.append({'_id': str(s['_id']), 'Waktu': s['Waktu'], 'Data': s['Data'], 'Rata-rata': s['Average']})
    return jsonify({'INI WEB SERVER APP 1': output})

@app.route("/info/bb", methods = ['GET','POST'])
def get_all_bb():
    databb = BB.find()
    output = []
    for s in databb:
        output.append({'_id': str(s['_id']), 'Waktu': s['Waktu'], 'Data': s['Data'], 'Rata-rata': s['Average']})
    return jsonify({'INI WEB SERVER APP 1': output})

@app.route("/info/dj", methods = ['GET','POST'])
def get_all_dj():
    datasuhu = DJ.find()
    output = []
    for s in datasuhu:
        output.append({'_id': str(s['_id']), 'Waktu': s['Waktu'], 'Data': s['Data'], 'Rata-rata': s['Average']})
    return jsonify({'INI WEB SERVER APP 1': output})

@app.route('/input/suhu', methods = ['GET',"POST"])
def post_suhu():
    _jsonSuhu = request.json['Suhu (celcius)']

    now = time.time()
    localtime = time.localtime(now)
    milliseconds = '%03d' % int((now - int(now)) * 1000)
    tgltime = time.strftime('%d-%b-%Y/%H:%M:%S,', localtime) + milliseconds
    print(len(hashkeysuhu))

    key = unhexlify(hashkeysuhu)
    iv = unhexlify(ivdcdsuhu)

    dataEncrypt = b64decode(str(_jsonSuhu).encode("utf-8"))
    decryptor = AES.new(key, AES.MODE_CBC, iv)

    ptxt = decryptor.decrypt(dataEncrypt)

    eHE = he.encryptFrac(float(ptxt[:4:].decode("utf-8")))

    dataHESuhu.append(eHE)

    dataSuhu.append({"Suhu": _jsonSuhu, "Waktu Terima": tgltime})
    print(dataSuhu)
    if (len(dataSuhu) == 100):
        sekarang = time.time()
        ms = '%03d' % int((sekarang - int(sekarang)) * 1000)
        tglkirimdoc = time.strftime('%d-%b-%Y/%H:%M:%S,', localtime) + ms

        rata= dataHESuhu[0]-dataHESuhu[0]

        for x in dataHESuhu:
            rata += x

        encryptor = AES.new(key, AES.MODE_CBC, iv)

        avgencrypt = encryptor.encrypt(pad(str(round(he.decode(he.decrypt(rata)) / len(dataHESuhu),2)).encode("utf-8"), AES.block_size))         #Proses Enkripsi AES Mode CBC
        avgencrypt = str(b64encode(avgencrypt).decode("utf-8"))

        data = {'Waktu': tglkirimdoc, 'Data': dataSuhu, 'Average': avgencrypt}.copy()
        dtkv = {'Waktu': tglkirimdoc, 'ky': hashkeysuhu, 'iv': ivdcdsuhu}.copy()
        Suhu.insert_one(data)
        credsh.insert_one(dtkv)
        print("Data pada Waktu " + tglkirimdoc + " telah ditambahkan ke database")
        print(request.headers)
        dataSuhu.clear()
        dataHESuhu.clear()
    return ""

@app.route('/input/bb', methods = ['GET',"POST"])
def post_BB():
    _jsonBB = request.json['BB (KG)']

    now = time.time()
    localtime = time.localtime(now)
    milliseconds = '%03d' % int((now - int(now)) * 1000)
    tgltime = time.strftime('%d-%b-%Y/%H:%M:%S,', localtime) + milliseconds
    print(len(hashkeybb))

    key = unhexlify(hashkeybb)
    iv = unhexlify(ivdcdbb)

    dataEncrypt = b64decode(str(_jsonBB).encode("utf-8"))
    decryptor = AES.new(key, AES.MODE_CBC, iv)

    ptxt = decryptor.decrypt(dataEncrypt)

    eHE = he.encryptFrac(float(ptxt[:4:].decode("utf-8")))

    dataHEBB.append(eHE)

    dataBB.append({"BB (KG)": _jsonBB, "Waktu Terima": tgltime})
    print(dataBB)
    if (len(dataBB) == 100):
        sekarang = time.time()
        ms = '%03d' % int((sekarang - int(sekarang)) * 1000)
        tglkirimdoc = time.strftime('%d-%b-%Y/%H:%M:%S,', localtime) + ms

        rata= dataHEBB[0]-dataHEBB[0]

        for x in dataHEBB:
            rata += x

        encryptor = AES.new(key, AES.MODE_CBC, iv)

        avgencrypt = encryptor.encrypt(pad(str(round(he.decode(he.decrypt(rata)) / len(dataHEBB),2)).encode("utf-8"), AES.block_size))
        avgencrypt = str(b64encode(avgencrypt).decode("utf-8"))

        data = {'Waktu': tglkirimdoc, 'Data': dataBB, 'Average': avgencrypt}.copy()
        dtkv = {'Waktu': tglkirimdoc, 'ky': hashkeybb, 'iv': ivdcdbb}.copy()
        BB.insert_one(data)
        credbb.insert_one(dtkv)
        print("Data pada Waktu " + tglkirimdoc + " telah ditambahkan ke database")
        print(request.headers)
        dataBB.clear()
        dataHEBB.clear()
    return ""

@app.route('/input/dj', methods = ['GET',"POST"])
def post_dj():
    _jsonDJ = request.json['DJ_(BPM)']

    now = time.time()
    localtime = time.localtime(now)
    milliseconds = '%03d' % int((now - int(now)) * 1000)
    tgltime = time.strftime('%d-%b-%Y/%H:%M:%S,', localtime) + milliseconds
    print(len(hashkeydj))

    key = unhexlify(hashkeydj)
    iv = unhexlify(ivdcddj)

    dataEncrypt = b64decode(str(_jsonDJ).encode("utf-8"))
    decryptor = AES.new(key, AES.MODE_CBC, iv)

    ptxt = decryptor.decrypt(dataEncrypt)

    eHE = he.encryptFrac(float(ptxt[:4:].decode("utf-8")))

    dataHEDJ.append(eHE)

    dataDJ.append({"DJ_(BPM)": _jsonDJ, "Waktu Terima": tgltime})
    print(dataDJ)
    if (len(dataDJ) == 100):
        sekarang = time.time()
        ms = '%03d' % int((sekarang - int(sekarang)) * 1000)
        tglkirimdoc = time.strftime('%d-%b-%Y/%H:%M:%S,', localtime) + ms

        rata= dataHEDJ[0]-dataHEDJ[0]

        for x in dataHEDJ:
            rata += x

        encryptor = AES.new(key, AES.MODE_CBC, iv)

        avgencrypt = encryptor.encrypt(pad(str(round(he.decode(he.decrypt(rata)) / len(dataHEDJ),2)).encode("utf-8"), AES.block_size))
        avgencrypt = str(b64encode(avgencrypt).decode("utf-8"))

        data = {'Waktu': tglkirimdoc, 'Data': dataDJ, 'Average': avgencrypt}.copy()
        dtkv = {'Waktu': tglkirimdoc, 'ky': hashkeydj, 'iv': ivdcddj}.copy
        DJ.insert_one(data)
        creddj.insert_one(dtkv)
        print("Data pada Waktu " + tglkirimdoc + " telah ditambahkan ke database")
        print(request.headers)
        dataDJ.clear()
        dataHEDJ.clear()
    return ""

@app.route('/user/add', methods = ['POST'])
def user_add():
    fullname = request.json["Full Name"]
    username = request.json["Username"]
    email = request.json["Email"]
    password = request.json["Password"]
    confirm = request.json["Confirm Password"]
    data = {'Full Name': fullname, 'Username': username, 'Email': email, 'Password': password, 'Confirm Password': confirm}
    User.insert(data)
    return str(data) + "\n berhasil input data ke Database ... BTW, INI WEB SERVER APP 1"

@app.route('/user', methods = ['GET', 'POST'])
def user():
    username = request.json["Username"]
    password = request.json["Password"]
    #data = {'Username': username, "Password": password}
    temu=User.find({"Username": username, "Password": password})
    output = []
    for s in temu:
        output.append({'Username': s['Username'], 'Password': s['Password']})
    return jsonify({'INI WEB SERVER APP 1': output})

if __name__ == '__main__':
   app.run(debug=True, host='0.0.0.0')
