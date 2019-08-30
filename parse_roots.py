import operator
import re
# import hashlib
import binascii

# import os
# myCmd = 'openssl x509 in'
# os.system(myCmd)

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

def root_name(cert_str):
    cert_str = cert_str.encode()
    cert = x509.load_pem_x509_certificate(cert_str, default_backend())

    # fingerprint = cert.fingerprint(hashes.SHA256())
    # print(fingerprint)
    fingerprint = binascii.hexlify(
            cert.fingerprint(hashes.SHA256())).decode('utf-8')

    print(f'fingerprint: {fingerprint}')

    issuer = str(cert.subject)

    try:
        result = re.search('CN=(.*)\)>', issuer)
        result = result.group(1).replace('\\', '')
        # print(result)
        result
    except:
        # print('===========')
        try:
            result = re.search('O=(.*),OU=', issuer)
            result = result.group(1).replace('\\', '')
            # print(result)
        except:
            result = re.search('O=(.*)\)>', issuer)
            result = result.group(1).replace('\\', '')
            # print(result)
    return result, fingerprint


# def hash_it(i):
#     i = i.encode()
#     hash_object = hashlib.sha256(i)
#     hex_dig = hash_object.hexdigest()
#     return hex_dig


with open('root_ca.txt', 'r') as f:
    data = f.readlines()

temp_cert = []
temp_cert_pem = ''
temp_cert_str = ''
flag_cert = False
root_info = []
server_hash = []

for i in data:
    if '-----BEGIN CERTIFICATE-----' in i:
        cert_info = []
        flag_cert = True

        temp_cert_pem += i
        temp_cert_str += i.strip()
        # print(i)
    elif flag_cert == True:
        if '-----END CERTIFICATE-----' in i:
            flag_cert = False

            temp_cert_pem += i
            temp_cert_str += i.strip()

            root_issuer, fingerprint = root_name(temp_cert_pem)
            # root_info.append(root_issuer)

            cert_info.append(root_issuer)

            # hash_str = hash_it(temp_cert_str)
            cert_info.append(fingerprint)
            server_hash.append(fingerprint)

            cert_info.append(temp_cert_pem)

            root_info.append(cert_info)

            temp_cert_pem = ''
            temp_cert_str = ''
            # print(i)
        else:
            temp_cert_pem += i
            temp_cert_str += i.strip()
            # print(i)

# for i in root_info:
#     print(i[2])


with open('mozilla_nss.txt', 'r') as f:
    data2 = f.readlines()

temp_cert_mozilla = []
temp_cert_pem_mozilla = ''
temp_cert_str_mozilla = ''
flag_cert_mozilla = False
root_info_mozilla = []
mozilla_hash = []

for i in data2:
    if '-----BEGIN CERTIFICATE-----' in i:
        cert_info = []
        flag_cert_mozilla = True

        temp_cert_pem_mozilla += i
        temp_cert_str_mozilla += i.strip()
        # print(i)
    elif flag_cert_mozilla == True:
        if '-----END CERTIFICATE-----' in i:
            flag_cert_mozilla = False

            temp_cert_pem_mozilla += i
            temp_cert_str_mozilla += i.strip()

            root_issuer, fingerprint = root_name(temp_cert_pem_mozilla)
            # root_info_mozilla.append(root_issuer)

            cert_info.append(root_issuer)

            # hash_str = hash_it(temp_cert_str_mozilla)
            cert_info.append(fingerprint)
            mozilla_hash.append(fingerprint)

            cert_info.append(temp_cert_pem_mozilla)

            root_info_mozilla.append(cert_info)


            temp_cert_pem_mozilla = ''
            temp_cert_str_mozilla = ''
            # print(i)
        else:
            temp_cert_pem_mozilla += i
            temp_cert_str_mozilla += i.strip()
            # print(i)


# list1 = []
# list2 = []

# list1 = root_info
# list2 = root_info_mozilla

list1_str = 'server_hash'
list2_str = 'mozilla_hash'

list1 = server_hash
list2 = mozilla_hash

temp1_yes = []
temp1_no = []

temp2_yes = []
temp2_no = []

# Remove duplicated
set1 = set(list1)
set2 = set(list2)

# Count empty rows
list1_empty = []
list2_empty = []
for i, l1 in enumerate(list1):
    l1 = str(l1)
    # if l1 == 'nan':
    #     list1[i] = '_no_value'
    #     # +2 is to print correct index to match Excel
    #     list1_empty.append((i, list1[i]))
    if l1 in list2:
        temp1_yes.append((i, l1))
    else:
        temp1_no.append((i, l1))

for i, l2 in enumerate(list2):
    l2 = str(l2)
    # if l2 == 'nan':
    #     list2[i] = '_no_value'
    #     # +2 is to print correct index to match Excel
    #     list2_empty.append((i, list2[i]))
    if l2 in list1:
        temp2_yes.append((i, l2))
    else:
        temp2_no.append((i, l2))


# TODO: find index in list for unique values
# for i, l1 in enumerate(set1):
#     if l1 in set2:
#         temp1_yes.append(str(l1))
#     else:
#         temp1_no.append(str(l1))
#
# for l2 in set2:
#     if l2 in set1:
#         temp2_yes.append(str(l2))
#     else:
#         temp2_no.append(str(l2))
        # print(l2)

# Sort
# temp1_yes = sorted(temp1_yes)
# temp2_yes = sorted(temp2_yes)

print(f'\n{list1_str} Total Roots: \t\t{str(len(list1))}')
# print(f'List1 Filled Rows: \t\t{len(list1)-len(list1_empty)}')
# # print(f'\nList1 Total: \t\t{str(len(list1))}')
# print(f'List1 Empty Rows: \t\t{len(list1_empty)}')
# for i, _ in enumerate(list1_empty):
#     print(f'{list1_empty[i][0]}\t{list1_empty[i][1]}')

print(f'\n{list2_str} Total Roots: \t\t{str(len(list2))}')
# print(f'List2 Filled Rows: \t\t{len(list2)-len(list2_empty)}')
# print(f'List2 Empty Rows: \t\t{len(list2_empty)}')
# for i, _ in enumerate(list2_empty):
#     print(f'{list2_empty[i][0]}\t{list2_empty[i][1]}')


print(f'\nRoots in {list1_str} only: {len(temp1_no)}')
for i, _ in enumerate(temp1_no):
    print(f'{temp1_no[i][0]}\t{temp1_no[i][1]}')


print(f'\nRoots in {list2_str} only: {len(temp2_no)}')
for i, _ in enumerate(temp2_no):
    print(f'{temp2_no[i][0]}\t{temp2_no[i][1]}')

shared_items = list(set(list1) & set(list2))
# print(f'type {type(shared_items)}')
print(f'\nItems Both Lists: {len(shared_items)}')
# for i, key_txt in enumerate(shared_items):
#     print(i, " ", key_txt)

'''
How many certificates are in List 1
How many certificates are in List 2

How many certificates only on List1
How many certificates only on List2

How many on Both lists

What certificates we should NOT have but are on web sites (when it should cause an Alert)
What certificates we should have and are used on web (causing an error)
'''

# Find the shared_items and get index from List1
shared_items_indexed = []

for i, key_txt in enumerate(shared_items):
    for ii, li_item in enumerate(list1):
        if key_txt == li_item:
            item_indexed = (ii, key_txt)
            shared_items_indexed.append(item_indexed)

# Order list by Index in tuple
shared_items_indexed = sorted(shared_items_indexed, key=lambda x: x[0])

print(f'shared_items_indexed on {list1_str} {len(shared_items_indexed)}')
for ind, i in enumerate(shared_items_indexed):
    print(f'index and i {ind} {i}')

# shared_items_indexed = set(shared_items_indexed)
# print(len(shared_items_indexed))

# Find the shared_item on List2
# temp_l1 = ''
# temp_l2 = ''
# matches_rows = []
#
# for i, key_txt in enumerate(shared_items_indexed):
#     # Correct the row number
#     row_l1 = key_txt[0]
#     # Get tuple values
#     temp_l1 = (row_l1, key_txt[1])
#     # Find match in List2
#     for iii, l2 in enumerate(list2):
#         if l2 == key_txt[1]:
#             row_iii = iii
#             # Assign CSV columns B, C, D, etc
#             # temp_l2 = (str(row_iii), list3[row_iii], list4[row_iii], key_txt[1])
#     # If matches are assigned to each temporary list
#     if temp_l1 and temp_l2:
#         # print(temp_l1, temp_l2)
#         # print('eeeee')
#         print(f'<{temp_l1[0]}> {temp_l1[1]}\n<{temp_l2[0]}> __{temp_l2[1]}__ <{temp_l2[2]}> {temp_l2[3]}\n')
#         matches_rows.append((temp_l1[0], temp_l2[0]))
#         temp_l1 = ''
#         temp_l2 = ''
#
# print(f'Rows matching {len(matches_rows)}')
# for item in matches_rows:
#     print(item)




print('-------------------------------------------------------------------\n')
print(f'Root info on {list1_str}\n')

# list1 = root_info
# list2 = root_info_mozilla

# SHARED CERTIFICATE
shared_cert_info = []
# temp_instance_with_problems = []

for index, root in enumerate(root_info):
    # print(val[1])
    for iindex, shared_root in enumerate(shared_items_indexed):
        temp_shared_cert_info = []
        if root[1] == shared_root[1]:
            # print(root_info)
            # print(f'Instance: {val[0]}')
            # print(f'Web URL: {val_usertrust[1]}')
            temp_shared_cert_info.append(root[0])
            temp_shared_cert_info.append(shared_root[1])
            temp_shared_cert_info.append(root[2])
            shared_cert_info.append(temp_shared_cert_info)

for ind, i in enumerate(shared_cert_info):
    if ind == 1:
        print(f'Root Name:\t{i[0]}\nFingerprint:\t{i[1]}\n{i[2]}')
# print(f'Quantity of Instances with Root problems: {len(instance_with_problems)}')
#
# print('-------------------------------------------------------------------\n')
#
# instance_name_old = ''
# instance_name_new = ''
#
# for i, val in enumerate(instance_with_problems):
#     if i == 0:
#         instance_name_old = val[0]
#         print(f'Instance: {instance_name_old}')
#
#     elif i != 0:
#         instance_name_new = val[0]
#
#         if instance_name_old != instance_name_new:
#             print(f'Instance: {instance_name_old}')
#             instance_name_old = instance_name_new
#
#         if instance_name_old == instance_name_new:
#             print(f'    Web URL: {val[1]}')











# site = []
# results = []
#
# for line in data:
#     line = line.strip()
#     if not line.strip() == '':
#         if "Hostname Validation:" in line:
#             _, hostname = line.split('Certificate matches ')
#             # print(part)
#             site.append(hostname)
#
#         if "Not After:" in line:
#             _, expiration = line.split('Not After:')
#             expiration = expiration.strip()
#             # print(expiration)
#             site.append(expiration)
#
#         if "Verified Chain:" in line:
#             _, chain = line.split('Verified Chain:')
#             chain = chain.strip()
#             chain = chain.lower()
#             # print(chain)
#             # print(chain)
#             site.append(chain)
#             results.append(site)
#             site = []
#
#     #     print(len(site))
#     #
#     #
#     #     if site not in results:
#     #         results.append(site)
#     # site = []
#         # results = set(results)
#
# usertrust = []
# comodo = []
#
# for index, sites in enumerate(results):
#     chain_text = sites[2]
#
#     if "usertrust" in chain_text:
#         # print(sites)
#         usertrust.append(sites)
#         # print(chain_text)
#
#     if "comodo" in chain_text:
#         # print(sites)
#         comodo.append(sites)
#         # print(chain_text)
#
#
#
#
#
# usertrust_sorted = sorted(usertrust, key=operator.itemgetter(0))
#
# print('-------------------------------------------------------------------\n')
# print('USERTrust Web Certificates ordered by Expiration Date\n')
# print(f'usertrust quantity {len(usertrust)}')
# for c in usertrust_sorted:
#     print(c)
#
#
# comodo_sorted = sorted(comodo, key=operator.itemgetter(0))
#
# print('-------------------------------------------------------------------\n')
# print('COMODO Web Certificates ordered by Expiration Date\n')
# print(f'COMODO quantity {len(comodo)}')
# for c in comodo_sorted:
#     print(c)
#
# print('-------------------------------------------------------------------\n')
# print('Instances with probable SSL issues\n')
#
#
# instance_with_problems = []
# # temp_instance_with_problems = []
#
# for index, val in enumerate(instance_url):
#     # print(val[1])
#     for iindex, val_usertrust in enumerate(usertrust_sorted):
#         temp_instance_with_problems = []
#         if val[1] == val_usertrust[1]:
#             # print(f'Instance: {val[0]}')
#             # print(f'Web URL: {val_usertrust[1]}')
#             temp_instance_with_problems.append(val[0])
#             temp_instance_with_problems.append(val_usertrust[1])
#             instance_with_problems.append(temp_instance_with_problems)
#
#
# print(f'Quantity of Instances with Root problems: {len(instance_with_problems)}')
#
# print('-------------------------------------------------------------------\n')
#
# instance_name_old = ''
# instance_name_new = ''
#
# for i, val in enumerate(instance_with_problems):
#     if i == 0:
#         instance_name_old = val[0]
#         print(f'Instance: {instance_name_old}')
#
#     elif i != 0:
#         instance_name_new = val[0]
#
#         if instance_name_old != instance_name_new:
#             print(f'Instance: {instance_name_old}')
#             instance_name_old = instance_name_new
#
#         if instance_name_old == instance_name_new:
#             print(f'    Web URL: {val[1]}')
