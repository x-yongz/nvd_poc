# NVD PoC v0.1

### How to use:
- Put your NVD API key into .env as "apiKey=[your API key]" or skip this and have lower API limits.
- Run main.py.
- Optional arguement --count.
- An output file (cpe_output.json) will be generated that holds the data of each CPE with its vulnerabilities and corresponding CWEs if any.
- A cache file will be created to hold unpopulated CPEs for future runs.
- If you have your own list of CPEs you want to use, ensure output file either do not exist or is in the correct format, then replace the cache with your own list.

### Arguments:
- --count specifies how many entries to populate, will start from the top of the list. Default 100.

### Note:
- Will save a cache of the entries that have not been populated and continue from there during the next run.
- If API returns an error, then script will attempt to check again with NVD up to 3 times, after which it will show as error. Error entries will be retried in the next run.
- Ensure you do not have the output (cpe_output.json) or cache (cache.json) in an open state while running the script as behavior cannot be guaranteed.
- Caution not to delete the output or cache else the list will not be in sync.
- To start from scratch, ensure both output and cache are deleted.

### Debug and other tools (debug.py)
- Check and verify NVD response
- Create cache file to populate specific CPEs

### Useful links:

CPE 2.3 format: https://en.wikipedia.org/wiki/Common_Platform_Enumeration

CVSS calculation: https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System 

### TODO:
- Overwrite/update mode, if user selects that then script will still ping NVD to get the data and overwrite whatever that already exists, if mode is not selected, script will skip the ones that already exist and have data populated (Need to account for No vulnerabilities returned entries).
