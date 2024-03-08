import json, os
import xml.etree.ElementTree as ET
from zipfile import ZipFile

def download_cpes(http, url):
    zipfile_name = url.split('/')[-1]

    resp = http.request('GET', url)

    if resp.status == 200:
        with open(zipfile_name, 'wb') as f:
            f.write(resp.data)
        with ZipFile(zipfile_name) as archive:
            archive.extractall()
        os.remove(zipfile_name)
    else:
        print('Error code: ' + resp.status)

    return zipfile_name[:-4]

def extract_cpes(filename):
    list_temp = []
    tree = ET.parse(filename)
    root = tree.getroot()
    namespace = {
        'cpe': 'http://cpe.mitre.org/dictionary/2.0',
        'cpe-23': 'http://scap.nist.gov/schema/cpe-extension/2.3'
    }

    count = 0
    for cpe_item in root.findall('.//cpe-23:cpe23-item', namespaces=namespace):
        cpe_name = cpe_item.attrib['name']
        list_temp.append(cpe_name)
        count+=1
    print(str(count) + ' CPE entries found!')
    
    return list_temp