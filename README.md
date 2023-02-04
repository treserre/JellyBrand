# JellyBrand
Tool to detect typosquatted / similar domains given a brand list on daily registered domains.
Work in progress.

**Feed**
The domain list is downloaded from the free newly registered domains from whoisds.com.
whoisds.com states that their newly registered domains can be freely used.
Consider that domains are ALWAYS 2 days old.
The script crafts the date to base64 and adds it to the URLpath to download the specific file on that date, only last 4 days available.
Once the domain list is downloaded, is stored on the /feed/ directory, so it does not need to be downloaded very single time.


**Dependencies**

# pip install pythonwhois-alt 
# pip install pyfiglet
# pip install jellyfish
# pip install zipfile
# pip install tabulate


**Distance calculation**

Using the jellyfish library to use 3 distance algorithms:
levenshtein <= 2
damerau leventshtein == 1
jaro winkler similarity >= 0.9

These are the personal recommendend values for a manegeable ratio of tp/fp. Depeding on the kind of brand name you are monitoring, you may want to change them.

Decrease both levensthein algorithms if you are seeing too many results.
Increase the jaro winkler float number if you are seeing too many results.

The name of the brands are also looked for in their entierity on each string.
