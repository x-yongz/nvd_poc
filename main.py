import argparse
import json
import os
import sys
import time
import urllib3
from dotenv import load_dotenv

from download_extract_cpes import download_cpes, extract_cpes

sys.path.append(os.path.dirname(__file__))

def main():
    load_dotenv()
    apiKey = os.getenv('apiKey')
    http = urllib3.PoolManager(num_pools=1, timeout=10.0)
    url = 'https://services.nvd.nist.gov'
    output_name = 'cpe_output.json'

    parser = argparse.ArgumentParser()
    parser.add_argument('--count', default=100, help='How many entries to populate, default 100')
    args = parser.parse_args()

    stopCount = int(args.count)
    
    print('Starting the process...')
    if os.path.exists('cache.json'):
        print('Cache exist, continuing from there...')
        with open('cache.json', 'r') as f:
            cpe_list = json.load(f)
    elif os.path.exists('official-cpe-dictionary_v2.3.xml'):
        print('Cache does not exist but CPE xml found, extracting the CPEs from file...')
        cpe_filename = 'official-cpe-dictionary_v2.3.xml'        
        cpe_list = extract_cpes(cpe_filename)
    else:
        print('Cache does not exist, downloading the CPE list from NVD...')
        cpe_filename = download_cpes(http, 'https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip')
        cpe_list = extract_cpes(cpe_filename)    

    print('Retrieving vulnerability data from NVD...')
    try:
        if os.path.exists('cpe_output.json'):
            with open('cpe_output.json', 'r') as f:
                cpe_list_all = json.load(f)
        else:
            cpe_list_all = {}
        cpe_list_done = [] # For removing done entries to the cache list should the script fails
        count = 0
        
        for cpe in cpe_list:
            count+=1
            if count > stopCount:
                break

            data = ping_nvd(http, url, apiKey, cpe)
            
            if data == 'error':
                cpe_list_all[cpe] = 'Error'
            elif data == 'blank':
                cpe_list_all[cpe] = 'No vulnerabilities returned'
            else:
                cpe_list_all[cpe] = extract_relevant_data(data)

            if data != 'error':
                cpe_list_done.append(cpe) 

    except Exception as e:
        print(e)
        print('Error! Saving the progress...')
        try:
            with open('cpe_output.json', 'w') as f:
                json.dump(cpe_list_all, f)
            cpe_list_done_set = set(cpe_list_done)
            leftover = [x for x in cpe_list if x not in cpe_list_done_set]
            with open('cache.json', 'w') as f:
                json.dump(leftover, f)
            print('Saved, Check cpe_output.json, do not edit cache.json')
            print('Re-run to continue where you left off')
        except Exception as e:
            print(e)
            print('Your unlucky day... Even the save failed, you will need to re-run from the last save...')

    print('Writing to file...')
    with open('cpe_output.json', 'w') as f:
        json.dump(cpe_list_all, f)
    cpe_list_done_set = set(cpe_list_done)
    leftover = [x for x in cpe_list if x not in cpe_list_done_set]
    with open('cache.json', 'w') as f:
        json.dump(leftover, f)
    print('All done! Check cpe_output.json, do not edit cache.json')

def ping_nvd(http, url, apiKey, cpe):
    output = []
    headers = {'apiKey' : apiKey}
    action = '/rest/json/cves/2.0?cpeName=' + cpe

    print('    ' + cpe)
    r = http.request('GET', url + action, headers=headers)
    time.sleep(1)

    for i in range(3):
        if r.status == 200:
            j = json.loads(r.data)
            if j['vulnerabilities']:
                return j
            else:
                return 'blank'
        else: # Retry if fail for up to 3 times
            time.sleep(3)
            continue
    return 'error'

def extract_relevant_data(data):
    cve_entries = {}
    cvssVerList = ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']

    for cve in data['vulnerabilities']:
        cve = cve['cve']
        
        description_value = ''
        for description in cve['descriptions']:
            if description['lang'] == 'en':
                description_value = description['value']
                break

        weaknesses = []
        if cve.get('weaknesses'):
            for weakness in cve['weaknesses']:
                weaknesses.append(weakness['description'][0]['value'])

        for version in cvssVerList:
            if version in cve['metrics']:
                cve_entries[cve['id']] = {
                    'cvssVersion' : cve['metrics'][version][0]['cvssData']['version'],
                    'baseScore' : cve['metrics'][version][0]['cvssData']['baseScore'],
                    # 'exploitabilityScore' : cve['metrics'][version][0]['exploitabilityScore'],
                    # 'impactScore' : cve['metrics'][version][0]['impactScore'],
                    # 'description' : description_value,
                    'cwes' : weaknesses
                }
                break

    return cve_entries

if __name__ == '__main__':
    main()