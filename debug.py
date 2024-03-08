# This file holds a set of debug tools or general tools you can use for special purposes

import json
import os
import urllib3

from dotenv import load_dotenv

# Returns the response when you do an API call to NVD with the CPE
def ping_nvd():
    # Edit as necessary
    cpeName = 'cpe:2.3:a:10up:safe_svg:1.9.10:*:*:*:*:wordpress:*:*'

    load_dotenv()
    apiKey = os.getenv('apiKey')
    http = urllib3.PoolManager(num_pools=1)
    url = 'https://services.nvd.nist.gov'

    output = []
    headers = {'apiKey' : apiKey}
    action = '/rest/json/cves/2.0?cpeName=' + cpeName

    r = http.request('GET', url + action, headers=headers)

    if r.status == 200:
        j = json.loads(r.data)
        with open('tempout.json', 'w') as f:
            json.dump(j, f)
        print('Check tempout.json for the output')
    else:
        print('Error: ' + str(r.status))

# Creates a new cache file with the entries you specify, useful if you only want to form the output file with certain CPEs
def create_cache():
    # Edit as necessary
    string_to_search = 'pillow'

    cache_new = []
    count = 0

    with open('cpe_dump.json' ,'r') as f:
        cache_original = json.load(f)
    
    for cpe in cache_original:
        if string_to_search in cpe:
            cache_new.append(cpe)
            count+=1

    with open('cache_new.json', 'w') as f:
        json.dump(cache_new, f)

    print(str(count) + ' entries created')
    print('Check cache_new.json for your new list')
    print('Rename it to cache.json before running the main script')

if __name__ == '__main__':
    # ping_nvd()
    create_cache()