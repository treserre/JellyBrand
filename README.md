# JellyBrand
Tool to detect typosquatted / similar domains given a brand list on daily registered domains.
Work in progress, this was my first personal python project, so expect sloppy code.


**Feed**

The domain list is downloaded from the free newly registered domains from whoisds.com.
whoisds.com states that their newly registered domains can be freely used.
Consider that domains are ALWAYS 2 days old.
The script crafts the date to base64 and adds it to the URLpath to download the specific file on that date, only last 4 days available.
Once the domain list is downloaded, is stored on the /feed/ directory, so it does not need to be downloaded very single time.

**Before your use**

Create 2 folders in the same directory of the main jellybrand script:

/brands/

/feed/

Inside /brands/ create a txt file with your brands or keywords to monitor, there is no need to add your brands' top-level domains.


**Dependencies**

pip install pythonwhois-alt

pip install pyfiglet

pip install jellyfish

pip install zipfile

pip install tabulate

Virustotal API key


**Distance calculation**

Using the jellyfish library to use 3 distance algorithms:
levenshtein <= 2
damerau leventshtein == 1
jaro winkler similarity >= 0.9

These are the personal recommendend values for a manegeable ratio of tp/fp. Depeding on the kind of brand name you are monitoring, you may want to change them.

Decrease both levensthein algorithms if you are seeing too many results.
Increase the jaro winkler float number if you are seeing too many results.

The name of the brands are also looked for in their entierity on each string.


# POC
Given a brand to be monitored named "cyberpunk" and checking it against newly registered domains on "January 1st 2077":

![image](https://user-images.githubusercontent.com/124435877/216766071-7b543c0c-e9f7-4dae-8de1-89e9014a0089.png)



## ROADMAP
* Adding or removing brands should overwrite the brands.txt file
* Monitoring list compares and alerts when changes are detected on the site.
* Response status
* MX records and alert if changes in comparison to last time checked.
* Monitoring list to be saved in a file, preferrably json format

![image](https://user-images.githubusercontent.com/124435877/216766239-e46144e1-60f1-4ec8-a46f-8ed80735a9ca.png)

