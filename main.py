import json
import requests

api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
apikey = input("Введите api-ключ для VirusTotal:\n")
print(f"Ваш api-ключ: {apikey}")
with open('input.txt') as inlist:
    for line in inlist:
        print(line)
#params = dict(apikey=apikey, resource='275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1577043276')
#response = requests.get(api_url, params=params)
#if response.status_code == 200:
#  result=response.json()
#  print(json.dumps(result, sort_keys=False, indent=4))
