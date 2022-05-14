import ipaddress
import boto3
import sys

_REGION = "us-east-1"
_ROLE_ARN_Format = "arn:aws:iam::{}:role/{}-AWS-Admin-Role"
_CIDR_Block_First_Octet = "192"
_Mask_To_Exclude = "/27"
_Accounts_List_To_Run =[""]


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

def process_overlap_cidrs(vpc_dict):
    overlapped_accounts=[]
    avoid_duplicate_flag=0
    for source in vpc_dict:
        if source in overlapped_accounts:
            continue
        for index,source_check in enumerate(vpc_dict[source][0]):
            if(list(source_check)[-3:]!=_Mask_To_Exclude):
                source_ip_cidr = ipaddress.IPv4Network(source_check)
                for dest in vpc_dict:
                    if source==dest:
                        continue
                    for index_1, dest_check in enumerate(vpc_dict[dest][0]):
                        dest_ip_cidr=ipaddress.IPv4Network(dest_check)
                        if source_ip_cidr.overlaps(dest_ip_cidr):
                            avoid_duplicate_flag=1
                            print(f"IP CIDRs overlap with the account {source}, {dest} for the range {source_ip_cidr}, {dest_ip_cidr} and {vpc_dict[source][1][index]}, {vpc_dict[dest][1][index_1]}")
                    if avoid_duplicate_flag==1:
                        overlapped_accounts.append(source)
                        overlapped_accounts.append(dest)
                        avoid_duplicate_flag=0
def main():
    vpc_dict={}
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
    process_overlap_cidrs(vpc_dict)

if __name__ == "__main__":
    main()