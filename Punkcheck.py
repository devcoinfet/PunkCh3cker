import os
import sys
import requests
import hashlib
import json

found_urls = []

def computeMD5hash(my_string):
    m = hashlib.md5()
    m.update(my_string.encode('utf-8'))
    return m.hexdigest()
    
def make_query(hostname):
     '''
     const site_hash = md5(hostname)

     const partial_hash = site_hash.slice(0, 5)
  
     const full_url = 'https://api.punkspider.io/api/partial-hash/' + partial_hash
     '''
  
     site_hash = hostname
     site_hash = computeMD5hash(site_hash)
     partial_hash = site_hash[0:5]
     full_url = 'https://api.punkspider.io/api/partial-hash/' + partial_hash
     return full_url,partial_hash,site_hash
     
     
def check_vulns(keys):
    flagged = []
    for i,v in keys.items():
        if int(v) > 0:
           flaggy = {}
           flaggy['Vuln_Type'] = i
           flaggy['Vuln_count'] = v
           print("VALID VULNS LOCATED FOR PARTIAL HASH MATCH!!!!!!!!!!!!!")
           flagged.append(flaggy)
    
    if flagged:
       return True,flagged
    
    
    
def deduce_vulns(hostname):
    full_url,partial_hash,full_hash = make_query(hostname)
    if full_url:
       print("Encoding Successful making web request")
       try:
          response = requests.get(full_url)
          if response:
             json_data = json.loads(response.text) 
  
             for key,value in json_data.items():
                 
                 partial = key[0:5]
                 if partial_hash == partial:
                    print("partial_hash_match {}".format(full_hash))
                    try:
                       truth_seeker,flagged = check_vulns(value['vulns'])
                       
                       if truth_seeker:
                          print(value['vulns'].values())
                          flagged_match = {}
                          flagged_match['full_url'] = full_url
                          flagged_match['rating'] = value['rating']
                          flagged_match['partial_match'] = partial_hash
                          flagged_match['full_hash'] = full_hash
                          flagged_match['flagged'] = flagged
                          found_urls.append(flagged_match)
                       
                    except Exception as ex6:
                       #print(ex6)
                       pass
       except Exception as ex2:
         #print(ex2)
         pass
         
hostnames = sys.argv[1]
lineList = [line.rstrip('\n') for line in open(hostnames)]
for hosts in lineList:
    try:
        deduce_vulns(hosts)
    except Exception as ex3:
      #print(ex3)
       pass
       
if found_urls:
   print(found_urls)
   with open('data.json', 'w') as f:
      json.dump(found_urls, f, indent=2)
