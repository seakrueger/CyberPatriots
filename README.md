# CyberPatriots
Scripts for the CyberPatriots competition 

## Windows
A Powershell script to a common set of challenges during the competition

### Set-Up
1. Download and unzip this repository to some location in the VM

2. Paste the list of approved usernames and admins into the users.txt file 

3. Paste the list of approved admins into the admins.txt file

Notes: 
  - Each name should be on a new line
  - Make sure there is not space after the name 

4. Open a powershell terminal **as Administrator** 

5. Run: `Set-ExecutionPolicy unrestricted -Scope Process`

### Running
1. Run: `./CyberSecurity.ps1` 

Notes: 
 - If the script is unable to find the path to any of the files run using `./CyberSecurity.ps1 -userfile {pathToFile} -adminfile {pathToFile} -secfile {pathToFile}`

2. From there select what you want the script to do, use option 1 to run everything  
