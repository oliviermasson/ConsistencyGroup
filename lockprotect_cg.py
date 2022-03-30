#! /usr/bin/env python3
"""
ONTAP REST API Sample Scripts
This script was developed to help demonstrate NetApp
technologies.  This script is not officially supported as a
standard NetApp product.
Purpose: Protect a Consistency Group with a lockvault relationship using ONTAP REST API.
Usage: python3 restore_cg_snapshot.py [-h] -c cluster -cg cg_name -sv src_svm_name [-dv dst_svm_name]
                                      [-dc dst_cluster] [-p sm_policy] [-s schedule] [-l locktype]
                                      -u API_USER -p API_PASS

Will create a snapvault relationship to auto-provisioning snaplock volume
By default it will create a destination CG name with <source cg name>_lock on local cluster
If provided it will create the lock env on a destination cluster
"""
import base64
import argparse
from dis import COMPILER_FLAG_NAMES
from getpass import getpass
from http.client import responses
import logging
from pickletools import stringnl_noescape
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
        print("Snapmirror job failed reason [{}]".format(job_status['message']))
        exit("Error : job state failure")
    elif job_status['state'] == "success":
        #print("Snapmirror job end successfully")
        return job_status['description'].split('/')[-1]
    else:
        job_response = requests.get(job_status_url, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status(
            cluster,
            job_status_url,
            job_status,
            headers_inc)

def check_dst_svm(
        cluster: str,
        svm: str,
        headers_inc: str):
    url = "https://{}/api/svm/svms".format(cluster)
    response = requests.get(
        url,
        headers=headers_inc,
        params={"name":svm},
        verify=False
    )
    if len(response.json()['records'])>0:
        return True
    else:
        exit("Error SVM [{}] does not exists on cluster [{}]".format(svm,cluster))

def check_svm_peered(
        cluster: str,
        svm1: str,
        svm2: str,
        headers_inc: str):
    url = "https://{}/api/svm/peers".format(cluster)
    response = requests.get(
        url,
        headers=headers_inc,
        params={"svm.name":svm1,"peer.svm.name":svm2},
        verify=False
    )
    if len(response.json()['records'])>0:
        return True
    else:
        exit("Error SVM [{}] and [{}] are not peered".format(svm1,svm2))

def get_cluster_name(
        cluster: str,
        headers_inc: str):
    url = "https://{}/api/cluster".format(cluster)
    response = requests.get(url,headers=headers_inc,verify=False)
    if response.status_code == 200:
        return response.json()['name']
    else:
        exit("Error communicating with cluster [{}]".format(cluster))
    

def check_cluster_peered(
        cluster1: str,
        cluster2: str,
        headers_inc: str):
    url = "https://{}/api/cluster/peers".format(cluster1)
    response = requests.get(url,headers=headers_inc,verify=False)
    if len(response.json()['records'])>0:
        peered=response.json()['records']
        for cluster_peered in peered:
            if (cluster_peered['name'] == get_cluster_name(cluster2,headers_inc)):
                return True
    else:
        exit("Error Cluster [{}] and [{}] are not peered".format(cluster1,cluster2))

def get_aggr_list(
        cluster: str,
        headers_inc: str):
    
    """ get data aggr name available ont this cluster"""
    url = "https://{}/api/storage/aggregates".format(cluster)
    response = requests.get(url,headers=headers_inc,verify=False)
    aggrlist=[]
    for aggr in response.json()['records']:
        aggrlist.append(aggr['name'])
    return aggrlist

def get_sm_policy_uuid(
        cluster: str,
        policy_name: str,
        headers_inc: str):
    """ retreive snapmirror policy UUID """
    url = "https://{}/api/snapmirror/policies".format(cluster)
    response = requests.get(
        url,
        params={"name": policy_name},
        verify=False,
        headers=headers_inc
    )
    if response.status_code != 200:
        exit("Error Failed to get snapmirror policy [{}] information".format(policy_name))
    return response.json()['records'][0]['uuid']

def modify_sm_policy(
        cluster: str,
        policyuuid: str,
        relationship_uuid: str,
        state: str,
        headers_inc:str):
    """ Modify SM relationship policy """
    url = "https://{}/api/snapmirror/relationships/{}".format(cluster,relationship_uuid)
    if (state is None):
        parameter={"policy.uuid": policyuuid}
    else:
        parameter={"state": state}
    response = requests.patch(
        url,
        json=parameter,
        headers=headers_inc,
        verify=False
    )
    response.json()

def protect_cg(
        cluster: str,
        cg_name: str,
        src_svm_name: str,
        dst_svm_name: str,
        dst_cluster: str,
        policy: str,
        schedule: str,
        locktype: str,
        headers_inc: str):

    """ validate env before being """
    if (dst_svm_name != src_svm_name):
        check_dst_svm(dst_cluster,dst_svm_name,headers_inc)
    if (cluster != dst_cluster):
        """ must check if Cluster are peered """
        check_cluster_peered(cluster,dst_cluster,headers_inc)
    if (dst_svm_name != src_svm_name):
        """ must check if SVM are peered """
        check_svm_peered(cluster,src_svm_name,dst_svm_name,headers_inc)

    """ get dst_cluster aggregate list """
    aggrlist = get_aggr_list(dst_cluster,headers_inc)

    """ retreive CG source UUID """
    search={
        "svm.name": src_svm_name,
        "name": cg_name
    }
    url = "https://{}/api/application/consistency-groups".format(cluster)
    response = requests.get(
        url,
        params=search,
        headers=headers_inc,
        verify=False
    )
    cglist=dict(response.json())['records']
    for cg in cglist:
        if cg['name'] == cg_name:
            cguuid=cg['uuid']
            break

    """ Get CG detail from CG uuid"""
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
    source_components=[]
    dest_components=[]
    index=1

    """ create destination snaplock volumes """
    print("Auto-Provision necessary destination snaplock volume")
    for vol in volumes:
        source_components.append(vol['name'])
        dst_size=int(vol['space']['size']*1.20)   # add 20% more size on dst volume too keep snapshot retention.
        aggr=aggrlist[index % len(aggrlist)]
        dst_vol_name="{}_lck".format(vol['name'])
        dest_components.append(dst_vol_name)
        # print(dst_size)
        # print(aggr)
        # print(dst_vol_name)
        index+=1

        """ Provision dest volumes """
        print("Create destination volume [{}]".format(dst_svm_name))
        url2 = "https://{}/api/storage/volumes".format(cluster)
        vol_detail = {
            "size": dst_size,
            "svm": {
                "name": dst_svm_name
            },
            "type": "dp",
            "snaplock": {
                "type": locktype,
                "retention": {
                    "minimum": "P7D"
                }
            },
            "aggregates": [{
                "name": aggr
            }],
            "name": dst_vol_name
        }
        response2 = requests.post(
            url2,
            json=vol_detail,
            headers=headers_inc,
            verify=False
        )
        if response2.status_code == 202:
            url_text = response2.json()
            job_status_url = "https://{}/{}".format(cluster,url_text['job']['_links']['self']['href'])
            job_response2 = requests.get(
                job_status_url,
                headers=headers_inc,
                verify=False)
            job_status = job_response2.json()
            check_job_status(
                cluster,
                job_status_url,
                job_status,
                headers_inc) 
        else:
            print("Create destination volume end with {}".format(response2.status_code))  
            exit(0)

        """ Get snapmirror policy uuid """
        policyuuid = get_sm_policy_uuid(dst_cluster,policy,headers_inc)

        """ create snapmirror lockvault relationship """
        src_path = "{}:{}".format(src_svm_name,vol['name'])
        dst_path = "{}:{}_lck".format(dst_svm_name,vol['name'])
        print("Create snapvault to snaplock relationship [{}] ---> [{}]".format(src_path,dst_path))
        relationship_detail={
            "source": {
                "path": src_path},
            "destination" : {
                "path": dst_path}
                #"path": "svm2_cluster1:testdp"}
        }
        url3 = "https://{}/api/snapmirror/relationships".format(dst_cluster) 
        response3 = requests.post(
            url3,
            json=relationship_detail,
            headers=headers_inc,
            verify=False
        )
        if response3.status_code == 202:
            #print("Accepted")
            url_text = response3.json()
            #url_text['job']['uuid']
            job_status_url = "https://{}/{}".format(dst_cluster,url_text['job']['_links']['self']['href'])
            job_response3 = requests.get(
                job_status_url,
                headers=headers_inc,
                verify=False)
            job_status = job_response3.json()
            #job_status['uuid']
            check_job_status(
                dst_cluster,
                job_status_url,
                job_status,
                headers_inc)
            relationship_uuid = job_status['description'].split('/')[-1] 
        else:
            print("Create lockvault relationship end with status_code [{}]\r\n message [{}]".format(response3.status_code,response3.json()['error']['message']))  
            exit(0)
        
        """ Modify SM relationship policy and initialize """
        #modify_sm_policy(dst_cluster,policyuuid,relationship_uuid,None,headers_inc)
        #modify_sm_policy(dst_cluster,None,relationship_uuid,"snapmirrored",headers_inc)
        """ initialize lockvault relationship """
        """ url4 = "https://{}/api/snapmirror/relationships/{}/transfers".format(dst_cluster,relationship_uuid)
        initialize_return = requests.post(
            url4,
            headers=headers_inc,
            verify=False
        )
        if initialize_return.status_code == 201:
            print("Relationship initialized [{}] <--- [{}]".format(dst_path,src_path))
        elif initialize_return.status_code == 202:
            print("Accepted")
            url_text = initialize_return.json()
            #url_text['job']['uuid']
            job_status_url = "https://{}/{}".format(dst_cluster,url_text['job']['_links']['self']['href'])
            job_response = requests.get(
                job_status_url,
                headers=headers_inc,
                verify=False)
            job_status = job_response.json()
            #job_status['uuid']
            relationship_uuid = check_job_status(
                dst_cluster,
                job_status_url,
                job_status,
                headers_inc)
            if relationship_uuid == None:
                errormessage="Failed to initialize snapmirror relationship"
                exit(errormessage)
        else:
            print("Error failed to initialize snapmirror relationship") """

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
        help="consistency group name")
    parser.add_argument(
        "-sv",
        "--src_svm_name",
        required=True,
        help="svm name")
    parser.add_argument(
        "-dv",
        "--dst_svm_name",
        help="destination svm name. If null will be <source svm name>_dst.\r\nThis SVM must aleady exists and must be already peered with source SVM.")
    parser.add_argument(
        "-dc",
        "--dst_cluster",
        help="destination cluster name. If null will be same cluster as source cluster.\r\nThis cluster must be already peered with source cluster.")
    parser.add_argument(
        "-po",
        "--policy",
        default="lockvault",
        help="snapmirror policy to use to create relationship. By default will use lockvault, which must already exist on dst_cluster")
    parser.add_argument(
        "-s",
        "--schedule",
        default="hourly",
        help="snapmirror schedule that will be set on created relationship. Default is hourly")
    parser.add_argument(
        "-l",
        "--locktype",
        choices=["compliance","enterprise"],
        default="enterprise",
        help="destination volume snaplock type : compliance or enterprise. Default is enterprise")
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

    if (ARGS.dst_cluster is None):
        ARGS.dst_cluster = ARGS.cluster
    if (ARGS.dst_svm_name is None):
        ARGS.dst_svm_name = "{}_dst".format(ARGS.src_svm_name)
    protect_cg(
        ARGS.cluster,
        ARGS.cg_name,
        ARGS.src_svm_name,
        ARGS.dst_svm_name,
        ARGS.dst_cluster,
        ARGS.policy,
        ARGS.schedule,
        ARGS.locktype,
        headers)