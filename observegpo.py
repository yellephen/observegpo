import asyncio
from msldap.commons.factory import LDAPConnectionFactory
import argparse

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

    return entries

    
    

#$searcher.Filter = "(&(objectCategory=organizationalUnit)(gplink=*$($name)*))"

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--constring', default="", help="The msldap connection string.")
    parser.add_argument('-u', '--user', default="", help="Repeat the sAMAccountName of the user running the query")
    args = parser.parse_args()
    
    query = f"(sAMAccountName={args.user})"
    currentuser = await client(args.constring, query,["distinguishedName"])

    #print(currentuser)
    userDN = currentuser[0]["attributes"]["distinguishedName"]
    print(f"Current user: {userDN}")
    print("")

    query = "(objectclass=groupPolicyContainer)"
    gpos = await client(args.constring, query,["name","displayname","gpcfilesyspath","whenCreated"])
    #print(f"GPOs found:{len(gpos)}")

    ou_tasks = []
    for gpo in gpos:
        #print(gpo["attributes"]["displayName"])
        name = gpo["attributes"]["name"]
        query = f"(&(objectCategory=organizationalUnit)(gplink=*{name}*))"
        ou_tasks.append(client(args.constring, query, attributes=["distinguishedname"]))

    ou_results = await asyncio.gather(*ou_tasks)
    backtrackindex = 0
    for ous in ou_results:
        print("===============================================")
        print("GPO Display Name: " + gpos[backtrackindex]["attributes"]["displayName"])
        #print(f"OUs linked to GPO: {len(ous)}")
        if (len(ous) == 0):
            print("[ ] No linked ous")
        for ou in ous:
            path = gpos[backtrackindex]["attributes"]["gPCFileSysPath"]
            print(f"[x] policy located at: {path}")
            whenCreated = gpos[backtrackindex]["attributes"]["whenCreated"]
            print(f"[x] Policy created at: {whenCreated}")
            print("[x] linked ou: " + ou["attributes"]["distinguishedName"])
            if is_user_in_ou(userDN,ou["attributes"]["distinguishedName"]):
                print("[x] user in this ou or a decendant")
            
            
        backtrackindex += 1

if __name__ == "__main__":
    asyncio.run(main())
