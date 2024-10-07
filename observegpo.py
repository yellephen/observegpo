import asyncio
from msldap.commons.factory import LDAPConnectionFactory
import argparse

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
    #parser.add_argument('-u', '--user', default="", help="The last name to use in the  combination.")
    args = parser.parse_args()
    
    query = "(objectclass=groupPolicyContainer)"
    gpos = await client(args.constring, query,["name","displayname","gpcfilesyspath"])
    #print(f"GPOs found:{len(gpos)}")

    ou_tasks = []
    for gpo in gpos:
        #print(gpo["attributes"]["displayName"])
        name = gpo["attributes"]["name"]
        query = f"(&(objectCategory=organizationalUnit)(gplink=*{name}*))"
        ou_tasks.append(client(args.constring, query, attributes=["displayname","name","distinguishedname","whencreated"]))

    ou_results = await asyncio.gather(*ou_tasks)
    backtrackindex = 0
    for ous in ou_results:
        print("===============================================")
        print("GPO: " + gpos[backtrackindex]["attributes"]["displayName"])
        #print(f"OUs linked to GPO: {len(ous)}")
        for ou in ous:
            print("[] linked ou: " + ou["attributes"]["distinguishedName"])
            path = gpos[backtrackindex]["attributes"]["gPCFileSysPath"]
            print(f"[] policy located at:{path}")
        backtrackindex += 1

if __name__ == "__main__":
    asyncio.run(main())
