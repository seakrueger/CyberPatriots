# CyberPatriots
Scripts for the CyberPatriots competition 

## Windows
Install: `Set-ExecutionPolicy unrestricted -Scope Process; wget https://raw.githubusercontent.com/skrueger-ftc/CyberPatriots/main/download-windows.ps1 -o download.ps1; .\download.ps1`

### Set-Up
1. Paste the list of approved usernames and admins into the users.txt file 
2. Paste the list of approved admins into the admins.txt file  
**Notes:**  
\- Each name should be on a new line  
\- There should not be a space after any name 

Notes: 
 - If the script is unable to find the path to any of the files run using `./CyberSecurity.ps1 -userfile {pathToFile} -adminfile {pathToFile} -secfile {pathToFile}`

2. From there select what you want the script to do, use option 1 to run everything  

## Debian
Install: `wget -O - https://raw.githubusercontent.com/skrueger-ftc/CyberPatriots/main/download-debian.sh > install.sh; chmod +x install.sh; ./install.sh`

### Set-Up
1. Paste users and admins into users.txt (one per line)
2. Paste admins into admins.txt (one per line)  
*note: running the install script and follow it's prompts will automatically add them"

Run script with `sudo ./CyberSecurity.sh`
