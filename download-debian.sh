curl -L https://api.github.com/repos/skrueger-ftc/CyberPatriots/tarball/main | tar xz
mv skrueger-ftc-CyberPatriots*/debian script/
cd script

echo "Users: <Paste here>"
users=($(sed '/^$/q'))
printf "%s\n" "${users[@]}" >> users.txt

echo "Admins: <Type \"finished\" when finished>"
read -rp ":" input
printf "%s\n" "${input}" >> admins.txt
printf "%s\n" "${input}" >> users.txt
while [[ $input != "finished" ]]; do
    read -rp ":" input
    if [[ $input != "finished" ]]; then
        printf "%s\n" "${input}" >> admins.txt
        printf "%s\n" "${input}" >> users.txt
    fi
done

cd ..
rm -r skrueger-ftc-CyberPatriots*

cd script
chmod +x ./CyberSecurity.sh
[ "$UID" -eq 0 ] || exec sudo ./CyberSecurity.sh

clear
echo "script is available in the script directory"
