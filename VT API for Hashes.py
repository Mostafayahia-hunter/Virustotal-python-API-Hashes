import requests
import time
import json
import pandas

file_path = str(input('please Enter The File Path: '))
domain_CSV = pandas.read_csv((file_path))

Hashes = domain_CSV['Hashes'].tolist()

API_key = 'YOUR API KEY'
url = 'https://www.virustotal.com/vtapi/v2/file/report'

parameters = {'apikey': API_key, 'resource': Hashes}
for i in Hashes:
    parameters = {'apikey': API_key, 'resource': i}

    response = requests.get(url=url, params=parameters)
    json_response = json.loads(response.text)

    if json_response['response_code'] <= 0:
        with open('not Found result.txt', 'a')  as notfound:
            notfound.write(i) and notfound.write("\tNOT found please Scan it manually\n")
    elif json_response['response_code'] >= 1:

        if json_response['positives'] <= 0:
            with open('Virustotal Clean result.txt', 'a')  as clean:
                clean.write(i) and clean.write("\t NOT malicious \n")
        else:
            with open('Virustotal Malicious result.txt', 'a')  as malicious:
                malicious.write(i) and malicious.write("\t Malicious") and malicious.write(
                    "\t this Hash Detectd by   " + str(json_response['positives']) + "  Solutions\n")
    time.sleep(15)
