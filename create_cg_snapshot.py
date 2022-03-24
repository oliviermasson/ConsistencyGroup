#! /usr/bin/env python3
"""
ONTAP REST API Sample Scripts
This script was developed to help demonstrate NetApp
technologies.  This script is not officially supported as a
standard NetApp product.
Purpose: Create a consistency group snapshot in a cluster using ONTAP REST API.
Usage: python3 creeate_cg_snapshot.py [-h] -c CLUSTER -cg cg_name -vs SVM_NAME -n snap_name [-t snap_type application|crash] [-l snap_label]
				      [-co snap_comment] [-u API_USER] [-p API_PASS]
"""
import base64
import argparse
from dis import COMPILER_FLAG_NAMES
from getpass import getpass
import logging
import texttable as tt
import requests
import datetime
import urllib3 as ur
ur.disable_warnings()
def check_job_status(
        cluster: str,
        job_status_url: str,
        job_status: str,
        headers_inc: str):
    """ Check job status"""
    if job_status['state'] == "failure":
        print(
            "Snapshot creation failed due to :{}".format(
                job_status['message']))
    elif job_status['state'] == "success":
        print("Snapshot created successfully")
    else:
        job_response = requests.get(
            job_status_url, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status(
            cluster,
            job_status_url,
            job_status,
            headers_inc)
def check_cg(cluster: str, svm_name: str, cg_name: str, headers_inc: str):
    """ Get CG key"""
    url = "https://{}/api/application/consistency-groups?svm.name={}".format(
        cluster, svm_name)
    response = requests.get(url, headers=headers_inc, verify=False)
    cgs = dict(response.json())['records']
    for i in cgs:
        if i['name'] == cg_name:
            return i['uuid']
    return None
def list_cg_snaps_details(
        cluster: str,
        cguuid: str,
        headers_inc: str):
    """ list available CG snapshots """
    url = "https://{}/api/application/consistency-groups/{}?fields=**".format(
        cluster, cguuid)
    response = requests.get(url, headers=headers_inc, verify=False)
    cgsnapdetails= dict(response.json())
    [print(key,':',value) for key,value in cgsnapdetails.items()]
def list_cg_snaps(
        cluster: str,
        cguuid: str,
        snap_name: str,
        headers_inc: str):
    """ list available CG snapshots """
    url = "https://{}/api/application/consistency-groups/{}/snapshots".format(
        cluster, cguuid)
    response = requests.get(url, headers=headers_inc, verify=False)
    cgsnapdetails= dict(response.json())['records']
    for snap in cgsnapdetails:
        if snap['name'] == snap_name:
            return snap_name
    return None
def create_cg_snap(
        cluster: str,
        svm_name: str,
        cg_name: str,
        snap_type: str,
        snap_label: str,
        snap_name: str,
        snap_comment: str,
        headers_inc: str):
    """ Check if cg_name exists """
    cguuid = check_cg(
        cluster,
        svm_name,
        cg_name,
        headers_inc)
    if cguuid is None:
        errormessage = "CG [{}] does not exists inside this SVM [{}]".format(cg_name,svm_name)
        exit(errormessage)
    existingsnap = list_cg_snaps(
        cluster,
        cguuid,
        snap_name,
        headers_inc)
    if existingsnap == snap_name:
        """ if a snapshot already exists with same, create a new one by adding a timestamp in its name """
        now = datetime.datetime.now()
        string_now = now.strftime("_%m-%d-%Y-%H-%M-%S")
        snap_name += string_now
    snap_data = {
        "name": snap_name,
        "consistency_type": snap_type,
        "comment": snap_comment,
        "snapmirror_label": snap_label
    }
    url = "https://{}/api/application/consistency-groups/{}/snapshots".format(cluster,cguuid)
    response = requests.post(
        url,
        headers=headers_inc,
        json=snap_data,
        verify=False)
    if response.status_code == 201:
            print("Snapshot [{}] Created inside CG [{}] on SVM [{}]".format(snap_name,cg_name,svm_name))
    elif response.status_code == 202:
            print("Accepted")
            url_text = response.json()
            job_status_url = "https://{}/{}".format(cluster,url_text['job']['_links']['self']['href'])
            job_response = requests.get(
                job_status_url,
                headers=headers_inc,
                verify=False)
            job_status = job_response.json()
            check_job_status(
                cluster,
                job_status_url,
                job_status,
                headers_inc)
    else:
            print("Error failed to create snapshot [{}] inside CG [{}]".format(snap_name,cg_name))
            
def parse_args() -> argparse.Namespace:
    """Parse the command line arguments from the user"""
    parser = argparse.ArgumentParser(
        description="This script will create a Consistency Group snapshot")
    parser.add_argument(
        "-c", "--cluster", required=True, help="API server IP:port details")
    parser.add_argument(
        "-cg",
        "--cg_name",
        required=True,
        help="Consistency Group where snapshot will be created.")
    parser.add_argument(
        "-vs",
        "--svm_name",
        required=True,
        help="SVM name where the CG is hosted.")
    parser.add_argument(
        "-t",
        "--snap_type",
        default="application",
        help="Snapshot type crash or application. Default is application.")
    parser.add_argument(
        "-l",
        "--snap_label",
        help="Snapshot snapmirror_label. Used only if this snapshot need to be replicated elsewhere")
    parser.add_argument(
        "-n",
        "--snap_name",
        required=True,
        help="Snapshot name. Is Mandatory")
    parser.add_argument(
        "-co",
        "--snap_comment",
        help="Snapshot comment")
    parser.add_argument(
        "-u",
        "--api_user",
        default="admin",
        help="API Username")
    parser.add_argument("-p", "--api_pass", help="API Password")
    parsed_args = parser.parse_args()
    # collect the password without echo if not already provided
    if not parsed_args.api_pass:
        parsed_args.api_pass = getpass()
    return parsed_args


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
    )
    ARGS = parse_args()
    BASE64STRING = base64.encodebytes(
        ('%s:%s' %
         (ARGS.api_user, ARGS.api_pass)).encode()).decode().replace('\n', '')
    headers = {
        'authorization': "Basic %s" % BASE64STRING,
        'content-type': "application/json",
        'accept': "application/json"
    }
    create_cg_snap(
        ARGS.cluster,
        ARGS.svm_name,
        ARGS.cg_name,
        ARGS.snap_type,
        ARGS.snap_label,
        ARGS.snap_name,
        ARGS.snap_comment,
        headers)
