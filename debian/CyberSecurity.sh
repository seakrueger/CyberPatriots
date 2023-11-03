#!/bin/bash
USERS='users.txt'
ADMINS='admins.txt'

BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

#============================================
# Removes Unapproved Users
#============================================
# Checks list of "approved" users vs users
#  on the system and removes unapproved users
#============================================
function removeUnapprovedUsers() {
    echo -e "${BLUE}--- Removing Unapproved Users ---${NC}"
    readarray -t approvedUsers < ${USERS}
    allUsers=(`cat /etc/passwd | grep '/home' | cut -d: -f1`)

    for user in "${allUsers[@]}"; do
        if [[ ! ${approvedUsers[@]} =~ $user ]]; then
            echo -n "Unapproved User found: ${user} - Remove? [y/n] "
            read -r confirm
            if [[ $confirm == "y" ]]; then
                userdel $user
            fi
        fi
    done
}

#============================================
# Add Missing Users
#============================================
# Checks the list of "approved" users and
#   adds any user who is missing
#============================================
function addMissingUsers() {
    echo -e "${BLUE}--- Adding Missing Users ---${NC}"
    readarray -t approvedUsers < ${USERS}
    allUsers=(`cat /etc/passwd | grep '/home' | cut -d: -f1`)

    for missingUser in "${approvedUsers[@]}"; do
        if [[ ! ${allUsers[@]} =~ $missingUser ]]; then
            echo -n "Missing User: ${missingUser} - Add? [y/n] "
            read -r confirm
            if [[ $confirm == "y" ]]; then
                useradd $missingUser
            fi
        fi
    done
}

#============================================
# Remove Unapproved Sudoers
#============================================
# Checks the list of "approved" sudoers and
#   removes unapproved users
#============================================
function removeUnapprovedSudoers() {
    echo -e "${BLUE}--- Removing Unapproved Sudoers ---${NC}"
    readarray -t approvedSudoers < ${ADMINS}
    allSudoers=(`cat /etc/group | grep sudo | awk -F':' '{ print $4 }' | awk -F',' -v OFS="\n" '{ $1=$1 }1'`)

    for sudoer in "${allSudoers[@]}"; do
        if [[ ! ${approvedSudoers[@]} =~ $sudoer ]]; then
            echo -n "Unapproved Sudoer found: ${sudoer} - Remove? [y/n] "
            read -r confirm
            if [[ $confirm == "y" ]]; then
                gpasswd -d ${sudoer} sudo
            fi
        fi
    done
}

#============================================
# Add Missing Sudoers
#============================================
# Checks the list of "approved" sudoers and
#   adds any user who is missing
#============================================
function addMissingSudoers() {
    echo -e "${BLUE}--- Adding Missing Sudoers ---${NC}"
    readarray -t approvedSudoers < ${ADMINS}
    allSudoers=(`cat /etc/group | grep sudo | awk -F':' '{ print $4 }' | awk -F',' -v OFS="\n" '{ $1=$1 }1'`)

    for missingSudoer in "${approvedSudoers[@]}"; do
        if [[ ! ${allSudoers[@]} =~ $missingSudoer ]]; then
            echo -n "Missing Sudoer: ${missingSudoer} - Add? [y/n] "
            read -r confirm
            if [[ $confirm == "y" ]]; then
                usermod -aG sudo $missingSudoer
            fi
        fi
    done
}

#============================================
# Start
#============================================
function startScript() {
    clear
    echo -e "${NC} 
 _______   _______  ______    __       ___       __   __  
|       \\ |   ____||   _  \\  |  |     /   \\     |  \\ |  | 
|  .--.  ||  |__   |  |_)  | |  |    /  ^  \\    |   \\|  | 
|  |  |  ||   __|  |   _  <  |  |   /  /_\\  \\   |  . \`  | 
|  '--'  ||  |____ |  |_)  | |  |  /  _____  \\  |  |\\   | 
|_______/ |_______||______/  |__| /__/     \\__\\ |__| \\__| 
                                                          
    1. Run All

    -- Users --
    2. Remove Unapproved Users              3. Add Missing Users
    4. Remove Unapproved Sudoers            5. Add Missing Sudoers

    -- Exit --
    6. Exit
"
    read -r option

    if [[ $option == "1" ]]; then
        removeUnapprovedUsers
        addMissingUsers
        removeUnapprovedSudoers
        addMissingSudoers
    elif [[ $option == "2" ]]; then
        removeUnapprovedUsers
    elif [[ $option == "3" ]]; then
        addMissingUsers
    elif [[ $option == "4" ]]; then
        removeUnapprovedSudoers
    elif [[ $option == "5" ]]; then
        addMissingSudoers
    elif [[ $option == "6" ]]; then
        exit
    fi
}

echo -e "${RED}--- DO THE FORESENSIC QUESTIONS FIRST --- DO THE FORENSIC QUESTIONS FIRST ----\n"
sleep 2
while true; do
   startScript 
done
