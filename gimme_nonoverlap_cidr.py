import ipaddress
import argparse
import boto3
import sys

_PRIVATE_SUPER_NET = "192.16.0.0/12"
_Accounts_List_To_Run =[""] #string list
_REGION = "us-east-1"
_CIDR_Block_First_Octet = "192"
_Mask_To_Exclude = "/30"
_ROLE_ARN_Format = "arn:aws:iam::{}:role/{}-AWS-Admin-Role"

def get_resource_from_cred(credentials, first_param):
    if credentials:
        resource = boto3.resource(first_param,
                                  region_name=_REGION,
                                  aws_access_key_id=credentials['AccessKeyId'],
                                  aws_secret_access_key=credentials['SecretAccessKey'],
                                  aws_session_token=credentials['SessionToken'])
    else:
        resource = boto3.resource(first_param, region_name=_REGION)
    return resource

def get_vpc(acct_id, credentials):
    res = get_resource_from_cred(credentials, "ec2")
    vpcs = res.vpcs.all()
    list_of_cidrs = []
    list_of_vpc_ids = []
    for a_vpc in list(vpcs):
        if a_vpc.owner_id != acct_id:
            continue
        if a_vpc.cidr_block[:3] == _CIDR_Block_First_Octet:
            list_of_cidrs.append(a_vpc.cidr_block)
            list_of_vpc_ids.append(a_vpc.vpc_id)
    return list_of_cidrs,list_of_vpc_ids

def get_vpc(acct_id, credentials):
    res = get_resource_from_cred(credentials, "ec2")
    vpcs = res.vpcs.all()
    list_of_cidrs = []
    list_of_vpc_ids = []
    for a_vpc in list(vpcs):
        if a_vpc.owner_id != acct_id:
            continue
        if a_vpc.cidr_block[:3] == _CIDR_Block_First_Octet:
            list_of_cidrs.append(a_vpc.cidr_block)
            list_of_vpc_ids.append(a_vpc.vpc_id)
    return list_of_cidrs,list_of_vpc_ids

def get_all_prefix_ranges(prefix_range):
    super_net= _PRIVATE_SUPER_NET
    prefix_ranges=list(ipaddress.ip_network(super_net).subnets(new_prefix=prefix_range))
    return prefix_ranges

def process_vpc_ranges(vpc_dict,all_prefixes):
    available_ip_ranges=[]
    for source_cidr in all_prefixes:  
        check_flag=0   
        for dest in vpc_dict:
            for dest_check in vpc_dict[dest][0]:
                if list(dest_check)[-3:] != _Mask_To_Exclude:
                    dest_ip_cidr=ipaddress.IPv4Network(dest_check)
                    if source_cidr.overlaps(dest_ip_cidr):
                        check_flag=1
                        break
            if check_flag==1:
                break
        if check_flag==0:
            available_ip_ranges.append(str(source_cidr))
    print("Please select any of the following IP ranges\n",available_ip_ranges)

def main():   
    parser = argparse.ArgumentParser(description='Get non-overlapping CIDR info',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--prefix-range', required=True,
                        help='Enter needed CIDR Prefix, Eg. 22,23,24 etc')
    args = parser.parse_args()
    prefix_range=int(args.prefix_range)
    vpc_dict ={}
    account_ids_list = _Accounts_List_To_Run
    sts = boto3.client('sts')
    for acct_id in account_ids_list:
        arn = _ROLE_ARN_Format.format(acct_id,acct_id)
        try:
            resp = sts.assume_role(RoleArn=arn, RoleSessionName="Overlap-Cidr-info")
        except Exception as e:
            sys.stderr.write("assume role got exception/{}/{}/{}\n".format(type(e),
                                                                            repr(e),
                                                                            str(e)))
        vpc_cidrs,vpc_ids=get_vpc(acct_id, resp.get('Credentials', {}) if resp else None)
        vpc_dict[acct_id]=[vpc_cidrs,vpc_ids]
    all_prefixes=get_all_prefix_ranges(prefix_range)
    process_vpc_ranges(vpc_dict,all_prefixes)
    
if __name__ == "__main__":
    main()
