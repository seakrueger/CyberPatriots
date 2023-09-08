Invoke-WebRequest -Uri https://github.com/skrueger-ftc/CyberPatriots/archive/refs/heads/main.zip -OutFile cyberpatriot-scripts.zip
Expand-Archive -Path cyberpatriot-scripts.zip -DestinationPath scripts
Set-Location -Path scripts\CyberPatriots-main\windows