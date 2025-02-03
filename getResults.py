#!/usr/bin/env python3

import os
import subprocess
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import nmap

# Configure your network range and API command
NETWORK_RANGE = "10.38.157.0/24"  # Replace with your network range
mwList = []
results_folder_path = '/home/nechifor/results_folder'

# Get all IPs in the network range
def get_ips_in_network():
    try:
        nm=nmap.PortScanner()
        result = subprocess.run(["/usr/bin/nmap", "-sn", NETWORK_RANGE], stdout=subprocess.PIPE, text=True)
        output = result.stdout
        ips = [line.split()[-1].strip("()") for line in output.splitlines() if "Nmap scan report" in line]
        #nm.scan(hosts=NETWORK_RANGE, arguments="-sn")
        #ips = nm.all_hosts()
        return ips
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []

# Ping a single IP address
def ping_ip(ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return False

# Get the MW token in order to use it for API commands
def getToken(mwIP, mwUsername, mwPasswd):
    baseurl = 'https://' + mwIP
    apiPath = '/auth/realms/keysight/protocol/openid-connect/token'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = { "grant_type" : "password", "username" : mwUsername, "password": mwPasswd, "client_id": "clt-wap" }

    try:
        response = requests.post(baseurl + apiPath, data=payload, headers=headers,verify=False)
    except Exception as e:
        #print(e)
        #print("Failed to get a valid token. Check if cluster is UP and running.")
        exit(1)

    return {'authorization': response.json()["access_token"]}

# Check which of the IPs are MW IPs
def get_mw_ips(ip, mwUsername, mwPasswd):

    try:
        response = requests.get('https://{}/api/v2/deployment/helm/cluster/releases'.format(ip), headers=getToken(ip, mwUsername, mwPasswd), verify=False)
        if "load-core" in response.text:
            mwList.append(ip)

    except requests.exceptions.RequestException as e:
        print("")
        #print(f"Error sending API command to {ip}: {e}")

# Get the exzisting results from a MW 
def get_results(ip, mwUsername, mwPasswd):
    new_res = 0
    try:
        response = requests.get('https://{}/api/v2/results'.format(ip), headers=getToken(ip, mwUsername, mwPasswd), verify=False)
        data = response.json()


        for i in range(0, len(data)):
            with open("/home/catalin-ubuntu/testIds.txt", "r") as file:
                lines = file.readlines()
                
            # Check if the target string is in any of the lines
            #for line in lines:
             #   if data[i]['id'] not in line:
            if any(data[i]['id'] in line for line in lines):
                    print("Result id " + data[i]['id'] + " already present in the list.")
                    #matches = 1
                    #return  # Exit if the string is found
            
                # If the string is not found, append it to the file and download the result
            else:
                new_res = new_res + 1
                with open("/home/catalin-ubuntu/testIds.txt", "a") as file:
                    file.write(data[i]['id'] + "\n")  # Append the string as a new line
                    print("Result id " + data[i]['id'] + " appended to the list.")
                    try:
                        print("Downloading file from " + '{}{}'.format(ip, data[i]['csvURL']))
                        print(data[i]['csvURL'])
                        response = requests.get('http://{}{}'.format(ip, data[i]['csvURL']),  headers=getToken(ip, mwUsername, mwPasswd), verify=False, stream=True)# Use `stream=True` for large files
                        response.raise_for_status()  # Raise an error for HTTP issues

                        # Save the file locally
                        os.makedirs(results_folder_path + '/' + ip, exist_ok=True)
                        testName = data[i]['displayName']
                        testName2 = testName.replace("/", "+")
                        print(testName2)
                        with open(os.path.join(results_folder_path + '/' + ip, testName2 + '-' + str(data[i]['endTime']) + '.zip'), "wb") as file:
                            for chunk in response.iter_content(chunk_size=8192):  # Download in chunks
                                file.write(chunk)

                        print(f"File downloaded successfully as {data[i]['displayName']+ '-' + str(data[i]['endTime']) + '.zip'}")

                    except requests.exceptions.RequestException as e:
                        print(f"Error downloading file: {e}")
        print("There were " + str(new_res) + " new results downloaded from MW " + ip)

    except requests.exceptions.RequestException as e:
        #print(f"Error sending API command to {ip}: {e}")
        print("")

# Main function
def main():
    print("Scanning network for devices...")
    ips = get_ips_in_network()
    print(f"Found {len(ips)} devices in the network.")

    with ThreadPoolExecutor(max_workers=10) as executor:
        for ip in ips:
            #if ping_ip(ip):
            executor.submit(get_mw_ips, ip, "admin", "admin")

    for ip in mwList:
        get_results(ip, "admin", "admin")

if __name__ == "__main__":
    main()
