Invoke-WebRequest -Uri https://github.com/skrueger-ftc/CyberPatriots/archive/refs/heads/main.zip -OutFile cyberpatriot-scripts.zip
Expand-Archive -Path cyberpatriot-scripts.zip -DestinationPath scripts
Remove-Item -Path cyberpatriot-scripts.zip
Move-Item -Path scripts\CyberPatriots-main\windows -Destination windows-script
Set-Location -Path windows-script