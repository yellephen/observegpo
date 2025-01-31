import asyncio
from msldap.commons.factory import LDAPConnectionFactory
import argparse
import os
from smbclient import listdir
from smbclient.path import isdir
import smbclient
import registrypol

def list_files_recursively(directory, username, password):
    files = []
    for dir_entry in smbclient.listdir(directory, username=username, password=password):
        if not isdir(directory+"\\"+dir_entry):
            files.append(directory+"\\"+dir_entry)
        if isdir(directory+"\\"+dir_entry):
            files.extend(list_files_recursively(directory+"\\"+dir_entry,username,password))           
    return files
            

def is_user_in_ou(user_dn, ou_dn):
    user_dn_parts = user_dn.split(',')
    ou_dn_parts = ou_dn.split(',')

    if len(user_dn_parts) < len(ou_dn_parts):
        return False

    for i in range(len(ou_dn_parts)):
        if user_dn_parts[-i-1].lower() != ou_dn_parts[-i-1].lower():
            return False

    return True

async def client(url,query,attributes):
    conn_url = LDAPConnectionFactory.from_url(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err

    #user = await ldap_client.get_user(user)
    
    entries = []
    async for entry, err in ldap_client.pagedsearch(
        query,
        attributes=attributes
    ):
        if err is not None:
            print(f"Error: {err}")
            break
        
        entries.append(entry)

    await ldap_client.disconnect()
    return entries

async def get_acl(url,dn):
    conn_url = LDAPConnectionFactory.from_url(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err
  
    entries = []
    entry = await ldap_client.get_objectacl_by_dn(dn)
    
    await ldap_client.disconnect()
    return entry

def ProcessSysVol(path, username, password):
    files = list_files_recursively(path, username, password)
    if len(files) == 0:
        print("[ ] No files found in SYSVOL for this policy.")
    else:
        print("[x] Paths to files in SYSVOL")
        for file in files:
            print(file)
            try:
                with smbclient.open_file(file,'w') as fdw:
                    print("     [x] The above file is writable by the smbuser passed.")
            except:
                print("     [ ] No write access to above file.")
            with smbclient.open_file(file, 'rb') as fd:
                if file.split(".")[-1] == "pol":
                    # Iterate over each registry value and print its details
                    print("Policy file found, dumping kvps.")
                    policy_data = registrypol.load(fd)
                    for value in policy_data.values:
                        if value.type == 0:
                            data = value.data
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_NONE")
                        elif value.type == 1:
                            data = value.data
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_SZ")
                        elif value.type == 2:
                            data = value.data
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_EXPAND_SZ")
                        elif value.type == 3:
                            data = value.data
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_BINARY")
                        elif value.type == 4:
                            data = int.from_bytes(value.data,'little')
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_DWORD")        
                        elif value.type == 5:
                            data = int.from_bytes(value.data,'big')
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_DWORD_BIG_ENDIAN")   
                        elif value.type == 6:
                            data = value.data
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_LINK")   
                        elif value.type == 7:
                            data = value.data
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_MULTI_SZ")   
                        elif value.type == 8:
                            data = value.data
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_RESOURCE_LIST")   
                        elif value.type == 11:
                            data = int.from_bytes(value.data,'little')
                            print(f"Key:{value.key}\{value.value} Value:{data} Type:REG_QWORD")                                                                                                                                                                                                                   




async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--constring', default="", required=True, help="The msldap connection string. eg. ldap+ntlm-password://TEST\\victim:<password>@10.10.10.2")
    parser.add_argument('-q', '--queryuser', default="", help="Will notify if this sAMAccountName is affected by each policy.")
    parser.add_argument('-t','--dcip', required=True, help="IP of a DC holding the SYSVOL to inspect.")
    parser.add_argument('-u','--smbuser', required=True, help="Username to connect to SYSVOL with")
    parser.add_argument('-p','--smbpassword', required=True, help="Password to connect to SYSVOL with")
    
    args = parser.parse_args()
    
    if args.queryuser != '':
        query = f"(sAMAccountName={args.queryuser})"
        currentuser = await client(args.constring, query,["distinguishedName"])

        #print(currentuser)
        userDN = currentuser[0]["attributes"]["distinguishedName"]
        print(f"Current user: {userDN}")
        print("")

    query = "(objectclass=groupPolicyContainer)"
    #Get nTSecurityDescriptor for users/groups assigned a GPO in ways other than OU
    gpos = await client(args.constring, query,["name","displayname","gpcfilesyspath","whenCreated","distinguishedName","nTSecurityDescriptor"])
    #print(f"GPOs found:{len(gpos)}")

   
    for gpo in gpos:
        
        name = gpo["attributes"]["name"]     
        print("===============================================")
        print("GPO Display Name: " + gpo["attributes"]["displayName"])
        path = gpo["attributes"]["gPCFileSysPath"]
        print(f"[x] policy located at: {path}")
        whenCreated = gpo["attributes"]["whenCreated"]
        print(f"[x] Policy created at: {whenCreated}")
        
        query = f"(&(objectCategory=organizationalUnit)(gplink=*{name}*))" 
        ou_results = await client(args.constring, query, attributes=["distinguishedname"])
        if (len(ou_results) == 0):
            print("[ ] No linked ous")
        for ou in ou_results:
            print("[x] linked ou: " + ou["attributes"]["distinguishedName"])
            if args.queryuser != '':
                if is_user_in_ou(userDN,ou["attributes"]["distinguishedName"]):
                    print("[x] user in this ou or a decendant")
        print(gpo)
        #maybe drop into pwsh to decode the SDDL or another way but it pulls out as bytes.
        #if it was run on windows it could just use an API
        #look at what the fucking SDDL pulls out as, wtf is \xeagfP
        #b'\x01\x00\x14\x9c\xe8\x01\x00\x00\x04\x02\x00\x00\x14\x00\x00\x00\xb4\x00\x00\x00\x04\x00\xa0\x00\x03\x00\x00\x00\x07R(\x00 \x00\x04\x00\x02\x00\x00\x00\xc2;\x0e\xf3\xf0\x9f\xd1\x11\xb6\x03\x00\x00\xf8\x03g\xc1\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x07Z8\x00 \x00\x00\x00\x03\x00\x00\x00\xbe;\x0e\xf3\xf0\x9f\xd1\x11\xb6\x03\x00\x00\xf8\x03g\xc1\xa5z\x96\xbf\xe6\r\xd0\x11\xa2\x85\x00\xaa\x000I\xe2\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x07Z8\x00 \x00\x00\x00\x03\x00\x00\x00\xbf;\x0e\xf3\xf0\x9f\xd1\x11\xb6\x03\x00\x00\xf8\x03g\xc1\xa5z\x96\xbf\xe6\r\xd0\x11\xa2\x85\x00\xaa\x000I\xe2\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x04\x004\x01\n\x00\x00\x00\x00\x00$\x00\xbd\x00\x0e\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00I\x98\xeagfP\x90\x856\xea\xe5\xe8\x00\x02\x00\x00\x00\n$\x00\xff\x00\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00I\x98\xeagfP\x90\x856\xea\xe5\xe8\x00\x02\x00\x00\x00\x00$\x00\xbd\x00\x0e\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00I\x98\xeagfP\x90\x856\xea\xe5\xe8\x07\x02\x00\x00\x00\n$\x00\xff\x00\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00I\x98\xeagfP\x90\x856\xea\xe5\xe8\x07\x02\x00\x00\x00\x00$\x00\xbd\x00\x0e\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00I\x98\xeagfP\x90\x856\xea\xe5\xe8\x00\x02\x00\x00\x00\n\x14\x00\xff\x00\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x02\x14\x00\xff\x00\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\x02\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x05\x02(\x00\x00\x01\x00\x00\x01\x00\x00\x00\x8f\xfd\xac\xed\xb3\xff\xd1\x11\xb4\x1d\x00\xa0\xc9h\xf99\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x02\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\t\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00I\x98\xeagfP\x90\x856\xea\xe5\xe8\x00\x02\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00I\x98\xeagfP\x90\x856\xea\xe5\xe8\x00\x02\x00\x00'

        parts = path.split('\\')
        parts[2] = args.dcip
        ippath = '\\'.join(parts)

        
        ProcessSysVol(ippath,args.smbuser,args.smbpassword)
    
if __name__ == "__main__":
    asyncio.run(main())
