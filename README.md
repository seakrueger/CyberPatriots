# CyberPatriots
Scripts for the CyberPatriots competition 

## Windows
### Set-Up
1. Download and unzip this repository to some location in the VM  
\- use `curl.exe -L https://api.github.com/repos/skrueger-ftc/CyberPatriots/tarball/main -o scripts.tgz | tar.exe -xzf scripts.tgz`
3. Paste the list of approved usernames and admins into the users.txt file 
4. Paste the list of approved admins into the admins.txt file  
**Notes:**  
\- Each name should be on a new line  
\- There should not be a space after any name 

### Running
1. Open a powershell terminal as **Administrator**
2. Run: `Set-ExecutionPolicy unrestricted -Scope Process | ./CyberSecurity.ps1`
 
Notes: 
 - If the script is unable to find the path to any of the files run using `./CyberSecurity.ps1 -userfile {pathToFile} -adminfile {pathToFile} -secfile {pathToFile}`

2. From there select what you want the script to do, use option 1 to run everything  
