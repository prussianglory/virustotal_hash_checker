import json
import requests
import time
import math

class VirusTotalHelper:
    def __init__(self):
        self.api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
        self.apikey = input("Введите api-ключ для VirusTotal:\n")        
        print(f"Ваш api-ключ: {self.apikey}")
        
    def load_hash_list(self):
        self.filepath = input("Введите путь к файлу:\n")        
        self.hashlist = []
        with open(self.filepath) as inlist:
            for line in inlist:                
                if line[-2] == ";" or line[-2] == '.':
                    line = line.replace(line[-2], '') 
                self.hashlist.append(line)
        #print(self.hashlist)
    def calculate_remaining_time(self):
        rem_time = math.ceil(len(self.hashlist) / 4)
        print(f"Ожидаемое время выполнения скрипта: {rem_time} минут")

    def get_md5_list(self):
        self.filepath = input("Введите путь к папке:\n")
        f = open(f"{self.filepath}/output.txt", "w")
        f.close()
        self.calculate_remaining_time()
        with open(f"{self.filepath}/output.txt", 'w') as output:
            for i in range(len(self.hashlist)):
                params = dict(apikey=self.apikey, resource=self.hashlist[i])
                response = requests.get(self.api_url, params=params)
                if response.status_code == 200:
                    result=response.json()
                    #print(json.dumps(result, sort_keys=False, indent=4)["md5"])
                    print(result['md5'])
                    output.write(result['md5']+'\n')
                else:
                    print(response.status_code)
                if i != 0 and (i+1)% 4 == 0 and (i+1) != len(self.hashlist):
                    time.sleep(60)
            

def main():
    helper = VirusTotalHelper()
    helper.load_hash_list()
    helper.get_md5_list()

if __name__ == "__main__":
    main()