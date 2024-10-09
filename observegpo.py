import asyncio
from msldap.commons.factory import LDAPConnectionFactory
import argparse
import os
from smbclient import listdir
from smbclient.path import isdir
import smbclient

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

def ProcessSysVol(path, username, password):
    files = list_files_recursively(path, username, password)
    if len(files) == 0:
        print("[ ] No files found in SYSVOL for this policy.")
    else:
        print("[x] Paths to files in SYSVOL")
        for file in files:
            print(file)

#$searcher.Filter = "(&(objectCategory=organizationalUnit)(gplink=*$($name)*))"

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--constring', default="", required=True, help="The msldap connection string.")
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
    gpos = await client(args.constring, query,["name","displayname","gpcfilesyspath","whenCreated"])
    #print(f"GPOs found:{len(gpos)}")

   
    for gpo in gpos:
        #print(gpo["attributes"]["displayName"])
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
        
        parts = path.split('\\')
        parts[2] = args.dcip
        ippath = '\\'.join(parts)

        
        ProcessSysVol(ippath,args.smbuser,args.smbpassword)
    
if __name__ == "__main__":
    asyncio.run(main())
