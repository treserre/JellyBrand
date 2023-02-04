import base64, requests, jellyfish, re, pyfiglet, json, pythonwhois 
from zipfile import ZipFile
from os import rename
from os.path import exists
from tabulate import tabulate


domain_list_notld = []
susp_matches = []
suspicious_domains = {"Domain": [], "Registrar": [], "Nameservers": []}
monitor_list = {"Domain": [], "Response": [], "VirusTotal": [], "MX Records": [], "Content Last Checked": [], "Alerts": []}
ascii_banner = pyfiglet.figlet_format("jELLyBraND") 
vt_api_key = "YOUR VIRUSTOTAL API KEY HERE" 
with open("brands/brands.txt", "r") as brand_str:
    brand_list = brand_str.read().splitlines()

print(f"{ascii_banner} by Roberto del Rio\n\n\n")

def main_menu():
    menu_option = input("What do you want to do?\n\n 1· Retrieve suspicious domains registered on a specific date.\n 2· See monitored domains and changes.\n 3· Configure my brands and keywords\n 99· Quit\n\n Choose a number: ")
    if menu_option == "1":
        jellybrand_table()
    elif menu_option == "2":
        monitoring_table()
    elif menu_option == "3":
        my_brands()
    elif menu_option == "99":
        print("\nMissing you already.")
    else:
        print("\nOption unavailable\n")
        main_menu()

def my_brands():
    print("\nBrands and keywords\n")
    print("\n".join(brand_list))
    brand_options()
    
def brand_options():
    mybrands_option = input("\n Options: (a)dd | (r)emove | (e)xit: ")
    if mybrands_option == "a":
        new_brand_add = input("\nWrite a new domain or keyword: ")
        brand_list.append(new_brand_add)
        print(f"{new_brand_add} added successfully.")
        brand_options()
    elif mybrands_option == "e":
        main_menu()
        

def jellybrand_table(): # main feature
#    print("\n\nWrite your brand name (lowercase)")
 #   brand_name = input()
    print("\nChoose a date to look for potential typosquatted/similar domains registered.")
    date_input = input("Format YYYY-MM-DD: ")
    
    ### We don't want to download the same file multiple times, we can't be that noisy
    if exists(f"feed/domains_{date_input}.txt") == True:
        print("\nDomain list for this day already exists and will not be downloaded again.\n\n")
    else:
        ### Convert to b64: whoisds.com follows the same file pattern to upload the daily free list in zip
        date_input_zip = date_input+".zip"
        date_ascii_bytes = date_input_zip.encode("ascii")
        date_base64_bytes = base64.b64encode(date_ascii_bytes)
        date_base64_str = date_base64_bytes.decode("ascii")
    
        ### The URI will look like this
        uri_request = f"https://www.whoisds.com//whois-database/newly-registered-domains/{date_base64_str}/nrd"
        print(f"\nThis is the crafted URL: {uri_request}\n\n")
    
        ### Using request module to get the zip file
        uri_output = requests.get(uri_request)
        with open("/tmp/domains.zip", "wb") as zipped_domains:
            zipped_domains.write(uri_output.content)
    
        ### Unzipping file
        with ZipFile("/tmp/domains.zip", "r") as zipped_domains2:
            zipped_domains2.extractall(path="feed/")
        rename("feed/domain-names.txt",f"feed/domains_{date_input}.txt") # overwrite the default name -- logging purposes and checking if already available
    
    ### Processing the list of domains and calculating distances
    with open(f"feed/domains_{date_input}.txt", "r") as domainlist_str:
    	domain_list = domainlist_str.readlines()
    	for domain in domain_list:
    		domain_list_notld.append(re.sub(r"\.[^.]*$", "", domain))
    print("\nCooking the jelly...\n")
    for brand_name in brand_list:
        for domain_name in domain_list_notld:
            if brand_name in domain_name:
                susp_matches.append(domain_name)  # domains containing the brand name
            elif jellyfish.levenshtein_distance(brand_name,domain_name) <= 2: 
                susp_matches.append(domain_name) # domains with 2 or less different characters
    
            elif jellyfish.damerau_levenshtein_distance(brand_name,domain_name) == 1:
                susp_matches.append(domain_name) # domains with 1 extra character or 1 character out of place
    
            elif jellyfish.jaro_winkler_similarity(brand_name,domain_name) >= 0.9:
                susp_matches.append(domain_name) # float number where 1 is identical and 0 is totally different - keep at 0.9!!! BEST RATIO TP/FP
    
    for domain in range(len(domain_list)):
        for suspicion in range(len(susp_matches)):
            if susp_matches[suspicion] in domain_list[domain]:
                suspicious_domains["Domain"].append(domain_list[domain].replace("\n","")) # latest replace function is used to remove line breaks hereditary from the original list

    ### removing duplicates....
    suspicious_domains["Domain"] = set(suspicious_domains["Domain"])                
    
    ### populating with whois info
    for suspentries in suspicious_domains["Domain"]:
        whois_req = pythonwhois.get_whois(suspentries)
        try:
            suspicious_domains["Registrar"].append("".join(whois_req["registrar"]))
        except:
            print(f"***ALERT*** Could not retrieve Registrar data for: {suspentries}\n")
            suspicious_domains["Registrar"].append("")
     #   try:
      #      suspicious_domains["Registrant"].append("|n".join(whois_req["contacts"]["registrant"]))
       # except:
        #    print(f"***ALERT*** Could not retrieve Registrant data for: {suspentries}\n")
         #   suspicious_domains["Registrant"].append("")
         # Registrant removed as they are commonly redacted for privacy
        try:
            suspicious_domains["Nameservers"].append("\n".join(whois_req["nameservers"]))
        except:
            print(f"***ALERT*** Could not retrieve Nameservers data for: {suspentries}\n")
            suspicious_domains["Nameservers"].append("")

    print(tabulate(suspicious_domains, headers="keys", tablefmt="fancy_grid", showindex="always"))
    post_jelly_prompt()


def post_jelly_prompt(): # actions to take after the jelly table was presented
    monitor_yn = input("\n\nDo you want to add domains to the monitor list? (y/n)\n")
    if monitor_yn == "y":
        add_domain()
        post_jelly_prompt()
    elif monitor_yn == "n":
        main_menu()
    else:
        print("I don't understand")

def add_domain(): # we willl be needing this more than once to add domains to the monitor table...
    add_dom_no = input("Which domain? Choose a number from the index: " )
    if int(add_dom_no) <= len(suspicious_domains["Domain"]):
        monitor_list["Domain"].append(list(suspicious_domains["Domain"])[int(add_dom_no)])
        print(f"\nDomain { list(suspicious_domains['Domain'])[int(add_dom_no)]} has been added to the monitoring list.\n")
    else:
        print("No domain with that value. Ensure you have entered the correct index number.")
        add_domain()

def monitoring_table():
    for monitos in monitor_list["Domain"]:
    ### populating VT data
        url = f"https://www.virustotal.com/api/v3/domains/{monitos}"
        headers = {"accept": "application/json", "x-apikey": vt_api_key}
        response = requests.get(url, headers=headers)
        result = json.loads(response.text)
        if "error" in result:
            monitor_list["VirusTotal"].append("Never reported")
        else:
            monitor_list["VirusTotal"].append(f'Malicious:  {result["data"]["attributes"]["last_analysis_stats"]["malicious"]}\nSuspicious: {result["data"]["attributes"]["last_analysis_stats"]["suspicious"]}')
    print(tabulate(monitor_list, headers="keys", tablefmt="fancy_grid", showindex="always"))
    
main_menu()