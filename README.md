# CyberPatriots
Scripts for the CyberPatriots competition 

## Windows
A Powershell script to a common set of challenges during the competition

### Set-Up
Download and unzip this repository to some location in the VM

Paste the list of approved usernames and admins into the users.txt file 
Paste the list of approved admins into the admins.txt file
Each name should be on a new line, make sure there is not space after the name.

Open a powershell terminal **as Administrator** 

Run: `Set-ExecutionPolicy unrestricted -Scope Process`

### Running
Run: `./CyberSecurity.ps1` 

If the script is unable to find the path to any of the files run using `./CyberSecurity.ps1 -userfile {pathToFile} -adminfile {pathToFile} -secfile {pathToFile}`

From there select what you want the script to do, use option 1 to run everything  
