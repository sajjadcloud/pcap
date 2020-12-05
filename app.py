import time

import dpkt
import os  # For File Manipulations like get paths, rename
from flask import Flask, flash, request, redirect, render_template, jsonify
from werkzeug.utils import secure_filename
import datetime

app = Flask(__name__)

app.secret_key = "fejfkle-efiwiwe-ewfklj-dcdsc"
# It will allow below 50MB contents only
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

path = os.getcwd()
# file Upload
UPLOAD_FOLDER = os.path.join(path, 'uploads')
if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = set(['pcap', 'pcapng'])


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def parsePCAP(pcap):
    ports = set()

    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                # print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
                continue
            ip = eth.data
            tcp = ip.data
            if tcp.dport:
                ports.add(tcp.dport)
        except Exception as exception:
            pass
    return sorted([x for x in iter(ports)])



@app.route('/', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({"response": "No file part"})
        file = request.files['file']
        if file.filename == '':
            return jsonify({"response": "No file selected for uploading"})
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ts = datetime.datetime.now().timestamp()
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], str(int(ts)) + filename))
            with open(os.path.join(app.config['UPLOAD_FOLDER'], str(int(ts)) + filename), 'rb') as fopen:
                pcap = dpkt.pcap.Reader(fopen)
                data = parsePCAP(pcap)
                return jsonify({
                    "data": data
                })
        else:
            return jsonify({"response": "Allowed file types are pcap, pcapng"})
