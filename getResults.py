#!/usr/bin/env python3

import os
import subprocess
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import nmap
import zipfile
import shutil

# Configure your network range and API command
NETWORK_RANGES = ["10.38.154.0/24", "10.38.155.0/24", "10.38.156.0/24","10.38.157.0/24","10.38.158.0/24","10.38.159.0/24"]  # Replace with your network range
#NETWORK_RANGES = ["10.38.157.170/32"]
#NETWORK_RANGES = ["10.38.157.0/24"]
mwList = []
results_folder_path = '/home/catalin-ubuntu/results_folder'
ips = []
# Get all IPs in the network range
def get_ips_in_network():
    try:
        for NETWORK_RANGE in NETWORK_RANGES:
        #nm=nmap.PortScanner()
            result = subprocess.run(["/usr/bin/nmap", "-sn", NETWORK_RANGE], stdout=subprocess.PIPE, text=True)
            output = result.stdout
            ipList = [line.split()[-1].strip("()") for line in output.splitlines() if "Nmap scan report" in line]
            #nm.scan(hosts=NETWORK_RANGE, arguments="-sn")
            #ips = nm.all_hosts()
            ips.append(ipList)
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
            print(mwList)

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
                    print("Result " + ip + " - " + data[i]['displayName'] + " appended to the list.")
                    try:
                        if(data[i]["tags"]["ResultSize"] != "0"):
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
                                with open(os.path.join(results_folder_path + '/' + ip, testName2 + '-' + str(data[i]['endTime']) +'.zip'), "wb") as file:
                                    for chunk in response.iter_content(chunk_size=8192):  # Download in chunks
                                        file.write(chunk)

                                print(f"File downloaded successfully as {data[i]['displayName']+ '-' + str(data[i]['endTime']) + '.zip'}")

                            except requests.exceptions.RequestException as e:
                                print(f"Error downloading file: {e}")
                    except KeyError as e:
                        print(f"ResultSize does not exist: {e}")
        print("There were " + str(new_res) + " new results downloaded from MW " + ip)

    except requests.exceptions.RequestException as e:
        #print(f"Error sending API command to {ip}: {e}")
        print("")

def get_unique_extract_dir(root, base_name):
    counter = 1
    extract_dir = os.path.join(root, f"{base_name}_{counter}")
    while os.path.exists(extract_dir):
        counter += 1
        extract_dir = os.path.join(root, f"{base_name}_{counter}")
    return extract_dir

def extract_zip_files(base_directory):
    for root, _, files in os.walk(base_directory):
        for file in files:
            if file.endswith(".zip"):
                zip_path = os.path.join(root, file)
                base_name = os.path.splitext(file)[0]
                extract_dir = get_unique_extract_dir(root, base_name)  # Get a unique folder name
                os.makedirs(extract_dir, exist_ok=True)
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    print(f"Extracted: {zip_path} -> {extract_dir}")
                except zipfile.BadZipFile:
                    print(f"Error: Corrupt zip file {zip_path}")
                except Exception as e:
                    print(f"Error extracting {zip_path}: {e}")


def remove_csv_files(base_directory):
    for root, _, files in os.walk(base_directory):
        for file in files:
            if file.endswith(".csv"):
                csv_path = os.path.join(root, file)
                try:
                    os.remove(csv_path)
                    print(f"Removed: {csv_path}")
                except Exception as e:
                    print(f"Error removing {csv_path}: {e}")

def get_unique_folder_name(base_path, prefix):
    counter = 1
    new_folder = os.path.join(base_path, f"{prefix}_{counter}")
    while os.path.exists(new_folder):
        counter += 1
        new_folder = os.path.join(base_path, f"{prefix}_{counter}")
    return new_folder

def check_for_userplane(base_directory, target_filename, csv_filenames, user_plane_csvs_dir):
    for root, _, files in os.walk(base_directory):
        for file in files:
            if file == target_filename:
                json_path = os.path.join(root, file)
                try:
                    with open(json_path, 'r') as json_file:
                        data = json.load(json_file)
                        if(data["ConfigType"] != "SBA"):
                            for i in range(0,len(data["Config"]["nodes"]["dn"]["ranges"])):
                                for j in range(0, len(data["Config"]["nodes"]["dn"]["ranges"][i]["userPlane"]["tigerObjective"])):
                                    if(data["Config"]["nodes"]["dn"]["ranges"][i]["userPlane"]["tigerObjective"][j]["enable"] or data["Config"]["nodes"]["ue"]["ranges"][i]["userPlane"]["tigerObjective"][j]["enable"]):
                                        parent_dir = os.path.dirname(root)
                                        unique_folder = get_unique_folder_name(user_plane_csvs_dir, "result")
                                        os.makedirs(unique_folder, exist_ok=True)

                                        for csv_filename in csv_filenames:
                                            csv_path = os.path.join(parent_dir, csv_filename)
                                            if os.path.exists(csv_path):
                                                shutil.copy(csv_path, unique_folder)
                                                print(f"Copied {csv_path} to {unique_folder}")
                                            else:
                                                print(f"CSV file not found: {csv_path}")

                                        # Check for the .zip file one level above the target directory
                                        # zip_file_path = os.path.join(os.path.dirname(parent_dir), file.replace('.json', '.zip'))
                                        # if os.path.exists(zip_file_path):
                                        #     shutil.copy(zip_file_path, unique_folder)
                                        #     print(f"Copied {zip_file_path} to {unique_folder}")
                                        # else:
                                        #     print(f"Zip file not found: {zip_file_path}")

                except Exception as e:
                    print(f"Error reading {json_path}: {e}")

def remove_subfolders_ending_in_2(parent_directory):
    for root, dirs, _ in os.walk(parent_directory, topdown=False):
        for dir_name in dirs:
            if dir_name.endswith("_2"):
                dir_path = os.path.join(root, dir_name)
                try:
                    shutil.rmtree(dir_path)  # Remove the directory and its contents
                    print(f"Removed folder: {dir_path}")
                except Exception as e:
                    print(f"Error removing {dir_path}: {e}")

# Main function
def main():
    # print("Scanning network for devices...")
    # ips = get_ips_in_network()
    # #print(ips)
    # print(f"Found {len(ips)} devices in the network.")

    # with ThreadPoolExecutor(max_workers=10) as executor:
    #     for ip in ips:
    #         for ip2 in ip:
    #         #if ping_ip(ip):
    #             print("here")
    #             print(ip2)
    #             executor.submit(get_mw_ips, ip2, "admin", "admin")

    # for ip in mwList:
    #     get_results(ip, "admin", "admin")

    #extract_zip_files("/home/catalin-ubuntu/results_folder")
    #extract_zip_files("/home/catalin-ubuntu/results_folder")
    #remove_subfolders_ending_in_2("/home/catalin-ubuntu/results_folder")


    #remove_csv_files("/home/catalin-ubuntu/results_folder")

    check_for_userplane(  "/home/catalin-ubuntu/results_folder", \
                            "config-data.bin", \
                            ["Fullcoreoverview_UserPlaneThroughput_UPFTxKbitss.csv",\
                            "Fullcoreoverview_UserPlaneThroughput_UPFRxKbitss.csv",\
                            "Fullcoreoverview_UserPlaneThroughput_RANTxKbitss.csv",\
                            "Fullcoreoverview_UserPlaneThroughput_RANRxKbitss.csv",\
                            "AgentStatistics.csv"],\
                            "/home/catalin-ubuntu/results_folder_user_plane")


if __name__ == "__main__":
    main()
