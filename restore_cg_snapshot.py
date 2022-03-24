
#! /usr/bin/env python3
"""
ONTAP REST API Sample Scripts
This script was developed by NetApp to help demonstrate NetApp
technologies.  This script is not officially supported as a
standard NetApp product.
Purpose: Create a consistency group snapshot in a cluster using ONTAP REST API.
Usage: python3 creeate_cg_snapshot.py [-h] -c CLUSTER -cg cg_name -vs SVM_NAME -n snap_name [-t snap_type application|crash] [-l snap_label]
                                                                [-co snap_comment] [-u API_USER] [-p API_PASS]
Copyright (c) 2020 NetApp, Inc. All Rights Reserved.
Licensed under the BSD 3-Clause “New” or Revised” License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
https://opensource.org/licenses/BSD-3-Clause
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
            "Snapmirror job failed due to :{}".format(
                job_status['message']))
        exit("Error : job state failure")
    elif job_status['state'] == "success":
        print("Snapmirror job end successfully")
        return job_status['description'].split('/')[-1]
    else:
        job_response = requests.get(
            job_status_url, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status(
            cluster,
            job_status_url,
            job_status,
            headers_inc)
def get_snapmirror_relationship(
        cluster: str,
        src_vol: str,
        src_svm: str,
        headers_inc: str):
    """ get snapmirror relationship from a source volume and return destination_path """
    url = "https://{}/api/snapmirror/relationships".format(cluster)
    relationship_search = {
        "list_destinations_only": True,
        "source.svm.name": src_svm,
        "source.path": "{}:{}".format(src_svm,src_vol),
        "fields": "**"
    }
    response=requests.get(
        url,
        params=relationship_search,
        verify=False,
        headers=headers_inc
    )
    smlist=response.json()['records']
    if len(smlist) > 1:
        exit("Multiple snapmirror relationship. Please check and choose the good one")
    paths={
        "src_path":smlist[0]['source']['path'],
        "dst_path":smlist[0]['destination']['path']
    }
    return paths
def get_cg_components(
        cluster: str,
        cg_name: str,
        svm_name: str,
        snap_name: str,
        headers_inc: str):
    """ get CG list and return UUID of searched CG"""
    """ search={
        "svm": {
            "name": svm_name
        },
        "consistency_groups": {
            "name": cg_name
        }    
    } """
    url = "https://{}/api/application/consistency-groups".format(cluster)
    response = requests.get(
        url,
        #params=search,
        headers=headers_inc,
        verify=False
    )
    cglist=dict(response.json())['records']
    for cg in cglist:
        if cg['name'] == cg_name:
            cguuid=cg['uuid']
            break
    """ Get CG detail with uuid"""
    url = "https://{}/api/application/consistency-groups/{}".format(cluster,cguuid)
    options={
        "fields": "**"
    }
    response = requests.get(
        url,
        headers=headers_inc,
        params=options,
        verify=False
    )
    cgdetail=response.json()
    volumes=cgdetail['volumes']
    #print("CG [{}] contains following volume".format(cg_name))
    for vol in volumes:
        #print(vol['name'])
        paths=get_snapmirror_relationship(cluster,vol['name'],svm_name,headers_inc)
        #print("actual source [{}] ---> dest [{}]".format(paths['src_path'],paths['dst_path']))
        restore_cg_snap(cluster,paths['dst_path'],paths['src_path'],snap_name,headers_inc)
def restore_cg_snap(
        cluster: str,
        src_path: str,
        dst_path: str,
        snap_name: str,
        headers_inc: str):
    relationship_data = {
        "source": {
            "path": src_path
            #"path": "svm2_cluster1:/cg/cgprod",
            #"consistency_group_volumes": "cglock1,cglock2,cglock3,cglock4"
        },
        "destination": {
            "path": dst_path
            #"path": dst_path,
            #"consistency_group_volumes": "cgvol1,cgvol2,cgvol3,cgvol4"
        },
        "restore": True
    }
    url = "https://{}/api/snapmirror/relationships/".format(cluster)
    response = requests.post(
        url,
        headers=headers_inc,
        json=relationship_data,
        verify=False
    )
    if response.status_code == 201:
        print("Relationship created [{}] <--- [{}]".format(dst_path,src_path))
    elif response.status_code == 202:
        print("Accepted")
        url_text = response.json()
        #url_text['job']['uuid']
        job_status_url = "https://{}/{}".format(cluster,url_text['job']['_links']['self']['href'])
        job_response = requests.get(
            job_status_url,
            headers=headers_inc,
            verify=False)
        job_status = job_response.json()
        #job_status['uuid']
        check_job_status(
            cluster,
            job_status_url,
            job_status,
            headers_inc)
        relationship_uuid = job_status['description'].split('/')[-1]
    else:
        print("Error failed to create snapmirror relationship")
    #relationship_detail = dict(response.json())['records']
    restore_detail = {
        "source_snapshot": snap_name
    }
    url2 = "https://{}/api/snapmirror/relationships/{}/transfers".format(cluster,relationship_uuid)
    restore_return = requests.post(
        url2,
        headers=headers_inc,
        json=restore_detail,
        verify=False
    )
    if restore_return.status_code == 201:
        print("Relationship restored [{}] <--- [{}] with snapshot [{}]".format(dst_path,src_path,snap_name))
    elif restore_return.status_code == 202:
        print("Accepted")
        url_text = restore_return.json()
        #url_text['job']['uuid']
        job_status_url = "https://{}/{}".format(cluster,url_text['job']['_links']['self']['href'])
        job_response = requests.get(
            job_status_url,
            headers=headers_inc,
            verify=False)
        job_status = job_response.json()
        #job_status['uuid']
        relationship_uuid = check_job_status(
            cluster,
            job_status_url,
            job_status,
            headers_inc)
        if relationship_uuid == None:
            errormessage="Failed to restore snapmirror relationship"
            exit(errormessage)
    else:
        print("Error failed to restore snapmirror relationship")
def parse_args() -> argparse.Namespace:
    """Parse the command line arguments from the user"""
    parser = argparse.ArgumentParser(
        description="This script will create a Consistency Group snapshot")
    parser.add_argument(
        "-c", "--cluster", required=True, help="API server IP:port details")
    parser.add_argument(
        "-s",
        "--src_path",
        #required=True,
        help="source path of the restoration relationship")
    parser.add_argument(
        "-d",
        "--dst_path",
        #required=True,
        help="destination path of the restoration relationship")
    parser.add_argument(
        "-n",
        "--snap_name",
        default="application",
        help="Snapshot name to restore to. Without will restore to the last snapshot available")
    parser.add_argument(
        "-v",
        "--svm_name",
        help="svm name")
    parser.add_argument(
        "-cg",
        "--cg_name",
        help="consistency group name")
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
    get_cg_components(
        ARGS.cluster,
        ARGS.cg_name,
        ARGS.svm_name,
        ARGS.snap_name,
        headers)
    """ restore_cg_snap(
        ARGS.cluster,
        ARGS.src_path,
        ARGS.dst_path,
        ARGS.snap_name,
        headers) """
