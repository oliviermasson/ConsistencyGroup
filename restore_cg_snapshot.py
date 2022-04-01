
#! /usr/bin/env python3
"""
ONTAP REST API Sample Scripts
This script was developed to help demonstrate NetApp
technologies.  This script is not officially supported as a
standard NetApp product.
Purpose: Restore a Consistency Group snapshot on source in a cluster using ONTAP REST API.
Usage: python3 restore_cg_snapshot.py [-h] -c cluster -cg cg_name -sv svm_name -n snap_name -u API_USER -p API_PASS
                                      [-s src_path] [-d dst_path]
By default it will search for an existing snapvault reltionship which protect this CG
And create a reversed snapmirror restore relationship to revert active filesystem of this CG from the snapshot choosen,
for all the flexvol inside this CG
You can also use this script to restore this CG on another existing volume, but in this case you must execute
this script for all flexvol which compose this CG
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
            job_status_url,
            job_status,
            headers_inc)

def get_snapmirror_destination_relationship_from_source(
        cluster: dict,
        src_vol: str,
        src_svm: str,
        headers_inc: str,
        return_only_volume_name: bool = False):
    """ get snapmirror relationship from a source volume and return destination_path """
    url = "https://{}/api/snapmirror/relationships".format(cluster['ip'])
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
    if (return_only_volume_name == False):
        paths={
            "src_path": smlist[0]['source']['path'],
            "dst_path": smlist[0]['destination']['path'],
            "dst_svm_name": smlist[0]['destination']['svm']['name'],
            "dst_svm_uuid": smlist[0]['destination']['svm']['uuid']
        }
    else:
        paths={"src_path":smlist[0]['source']['path']}
    return paths

def restore_cg_components(
        cluster: dict,
        cg_name: str,
        svm_name: str,
        snap_name: str,
        headers_inc: str):
    """ restore CG snapshot to original location """

    """ Get CG UUID """
    url = "https://{}/api/application/consistency-groups".format(cluster['ip'])
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
    url = "https://{}/api/application/consistency-groups/{}".format(cluster['ip'],cguuid)
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
    """ for each CG component get existing snapmirror relationship to performe snapmirror Restore """
    for vol in volumes:
        #print(vol['name'])
        vaultpaths=get_snapmirror_destination_relationship_from_source(cluster['ip'],vol['name'],svm_name,headers_inc)
        #print("actual source [{}] ---> dest [{}]".format(vaultpaths['src_path'],vaultpaths['dst_path']))
        restore_cg_snap(cluster,vaultpaths['dst_path'],vaultpaths['src_path'],snap_name,headers_inc)

def check_dst_svm(
        cluster: dict,
        svm: str,
        headers_inc: str):
    """ check if SVM exist """
    url = "https://{}/api/svm/svms".format(cluster['ip'])
    response = requests.get(
        url,
        headers=headers_inc,
        params={"name":svm},
        verify=False
    )
    if len(response.json()['records'])>0:
        return True
    else:
        exit("Error SVM [{}] does not exists on cluster [{}]".format(svm,cluster['name']))

def check_svm_peered(
        cluster: dict,
        svm1: str,
        svm2: str,
        headers_inc: str):
    """ check if SVM are peered """
    url = "https://{}/api/svm/peers".format(cluster['ip'])
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
    """ check if cluster exists """
    url = "https://{}/api/cluster".format(cluster)
    response = requests.get(url,headers=headers_inc,verify=False)
    if response.status_code == 200:
        return response.json()['name']
    else:
        exit("Error communicating with cluster [{}]".format(cluster))
    
def check_cluster_peered(
        cluster1: dict,
        cluster2: dict,
        headers_inc: str):
    """ check if Cluster are peered """
    url = "https://{}/api/cluster/peers".format(cluster1['ip'])
    response = requests.get(url,headers=headers_inc,verify=False)
    if len(response.json()['records'])>0:
        peered=response.json()['records']
        for cluster_peered in peered:
            if (cluster_peered['name'] == cluster2['name']):
                return True
    else:
        exit("Error Cluster [{}] and [{}] are not peered".format(cluster1['name'],cluster2['name']))

def check_and_create_dst_volume(
            dst_cluster: dict,
            dst_svm_name: str,
            restvol: str,
            cluster: dict,
            srcvol: str,
            headers_inc: str):
        """ check destination restore volume and create them if needed """
        restvolsize = (get_volume_detail(cluster,srcvol,headers_inc))['size']
        url = "https://{}/api/"

def restore_alternate_cg_snap(
        cluster: dict,
        cg_name: str,
        svm_name: str,
        dst_cg_name: str,
        dst_vol: str,
        dst_svm_name: str,
        dst_cluster: dict,
        snap_name: str,
        headers_inc: str):
    """ Restore CG to alternate auto-provisionned volume """

    """ retreive CG source UUID """
    search={
        "svm.name": svm_name,
        "name": cg_name
    }
    url = "https://{}/api/application/consistency-groups".format(cluster['ip'])
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
    url = "https://{}/api/application/consistency-groups/{}".format(cluster['ip'],cguuid)
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
    """ for each CG component get the existing destination snapvault volume """
    for vol in volumes:
        # source_components.append(vol['name'])
        # source_components.append(get_snapmirror_destination_relationship_from_source(cluster,vol['name'],svm_name,headers_inc,True))
        # dest_components.append("{}{}".format(dst_vol,index))
        vaultpaths=get_snapmirror_destination_relationship_from_source(cluster,vol['name'],svm_name,headers_inc)
        src_path=vaultpaths['dst_path']
        if (dst_svm_name != vaultpaths['dst_svm_name']):
            check_svm_peered(dst_cluster,dst_svm_name,vaultpaths['dst_svm_name'],headers_inc)
        dst_path="{}:{}{}".format(dst_svm_name,dst_vol,index)
        # check if restore destination volume already exists
        # if not they will be created based on source volume size
        check_and_create_dst_volume(
            dst_cluster,
            dst_svm_name,
            "{}{}".format(dst_vol,index),
            cluster,
            src_path.split(":")[-1]
            headers_inc)
        restore_cg_snap(cluster,src_path,dst_path,snap_name,headers_inc)
        index+=1
        
        """ create snapmirror restore relationship with consistency group component and auto-provision """

def restore_cg_snap(
        cluster: dict,
        src_path: str,
        dst_path: str,
        snap_name: str,
        headers_inc: str):
    """ create a snapmirror restore relationship beetwen src_path and dst_path provided """
    """ SVM peer and Cluster peer must already be confirmed """
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
        "restore": True,
        "create_destination.enabled": True
    }
    url = "https://{}/api/snapmirror/relationships/".format(cluster['ip'])
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
        job_status_url = "https://{}/{}".format(cluster['ip'],url_text['job']['_links']['self']['href'])
        job_response = requests.get(
            job_status_url,
            headers=headers_inc,
            verify=False)
        job_status = job_response.json()
        #job_status['uuid']
        check_job_status(
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
    """ Initiate RST transfer for the existing snapmirror relationship """
    url2 = "https://{}/api/snapmirror/relationships/{}/transfers".format(cluster['ip'],relationship_uuid)
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
        job_status_url = "https://{}/{}".format(cluster['ip'],url_text['job']['_links']['self']['href'])
        job_response = requests.get(
            job_status_url,
            headers=headers_inc,
            verify=False)
        job_status = job_response.json()
        #job_status['uuid']
        relationship_uuid = check_job_status(
            job_status_url,
            job_status,
            headers_inc)
        if relationship_uuid == None:
            errormessage="Failed to restore snapmirror relationship"
            exit(errormessage)
    else:
        print("Error failed to restore snapmirror relationship")

def get_cluster_detail(
        cluster: str,
        headers_inc: str):
    """ return cluster name and mgmt interface IP address """
    url = "https://{}/api/cluster".format(cluster)
    response = requests.get(url,verify=False,headers=headers_inc)
    if (response):
        detail={"name": response.json()['name'],"ip": response.json()['management_interfaces'][0]['ip']['address']}
        return  detail
    else:
        exit("Error failed to communicate with cluster @ [{}]".format(cluster))

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
        help="Snapshot name to restore to. Without will restore to the last snapshot available")
    parser.add_argument(
        "-sv",
        "--svm_name",
        help="source svm name")
    parser.add_argument(
        "-cg",
        "--cg_name",
        help="consistency group name")
    parser.add_argument(
        "-dav",
        "--dst_vol",
        help="destination volume name. Will suffix with digit for each consistency group component\r\nThis argument is only use to restore into anternate volume")
    parser.add_argument(
        "-dcg",
        "--dst_cg_name",
        help="destination consistency group name. If Null will be <source cg name>_dst\r\nThis argument is only use to restore into anternate volume")
    parser.add_argument(
        "-dv",
        "--dst_svm_name",
        help="destination svm name. If null will be <source svm name>_dst.\r\nThis SVM must aleady exists and must be already peered with source SVM.\r\nThis argument is only use to restore into anternate volume")
    parser.add_argument(
        "-dc",
        "--dst_cluster",
        help="destination cluster name. If null will be same cluster as source cluster.\r\nThis cluster must be already peered with source cluster.\r\nThis argument is only use to restore into anternate volume")
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

    cluster1 = get_cluster_detail(ARGS.cluster,headers)
    
    if ( (ARGS.src_path is None or ARGS.dst_path is None) and ARGS.dst_vol is None):
        """ restore to source volume based on already existing snapmirror relationship """
        print("Restore to existing sources volumes")
        restore_cg_components(
            cluster1,
            ARGS.cg_name,
            ARGS.svm_name,
            ARGS.snap_name,
            headers)
    elif (ARGS.dst_vol is not None):
        """ restore to destination volume with auto-provision """   
        print("Restore to alternate volumes")
        if (ARGS.dst_cg_name is None):
            ARGS.dst_cg_name = "{}_dst".format(ARGS.cg_name)
        if (ARGS.dst_cluster is None):
            ARGS.dst_cluster = ARGS.cluster
        if (ARGS.dst_svm_name is None):
            ARGS.dst_svm_name = ARGS.svm_name
        cluster2 = get_cluster_detail(ARGS.dst_cluster,headers)
        restore_alternate_cg_snap(
            cluster1,
            ARGS.cg_name,
            ARGS.svm_name,
            ARGS.dst_cg_name,
            ARGS.dst_vol,
            ARGS.dst_svm_name,
            cluster2,
            ARGS.snap_name,
            headers)
    else:
        """ restore to existing alternate destination volume provided through src_path """
        """ need to execute this command for each CG volume component """
        # snapmirror restore cannot auto-provision destination volume
        print("Restore to another existing volume")
        restore_cg_snap(
            cluster1,
            ARGS.src_path,
            ARGS.dst_path,
            ARGS.snap_name,
            headers)
