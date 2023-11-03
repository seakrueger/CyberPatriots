#!/bin/bash
USERS='users.txt'
ADMINS='admins.txt'

PASSWORD='SecurePassword!123'

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
# Add New Group
#============================================
# Creates a group 
#   and adds users
#============================================
function addGroup() {
    echo -e "${BLUE}--- Adding New Group ---${NC}"
    read -rp "Add new group? [y/n] " confirm
    if [[ $confirm == "y" ]]; then
        read -rp "Group name? " name
        read -rp "GID? <enter to skip> " gid

        # Create group
        if [[ -z "${gid}" ]]; then
            groupadd ${name} 
        else
            groupadd -g ${gid} ${name}
        fi

        # Add users
        users=(`cat /etc/passwd | grep '/home' | cut -d: -f1`)
        echo "Users: ${users[@]}"
        echo "Type users to be added: <\"q\" to quit>"
        while true; do
            read -rp ":" user
            if [ "${user}" = "q" ]; then
                break
            fi

            if id "$user" &>/dev/null; then
                sudo usermod -aG "${name}" "${user}"
            else
                echo "User '${user}' does not exist."
            fi
        done
    fi
}

#============================================
# Enable Password Policy 
#============================================
# Setups a  password policy via 
#  /etc/login.defs
#============================================
function setupPasswordPolicy {
    echo -e "${BLUE}--- Setting Up Password Policy ---${NC}"
    cp /etc/login.defs /etc/login.defs.bak
    cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
    echo "Created backups of logins.defs and common-password"

    sed -i -e '/^PASS_MAX_DAYS/ s/.*/PASS_MAX_DAYS 60/' /etc/login.defs
    sed -i -e '/^PASS_MIN_DAYS/ s/.*/PASS_MIN_DAYS 5/' /etc/login.defs
    sed -i -e '/^PASS_WARN_AGE/ s/.*/PASS_WARN_AGE 7/' /etc/login.defs 
}

#============================================
# Update Passwords 
#============================================
# Updates the password for all Users
#  for users and admins
#============================================
function updatePasswords {
    echo -e "${BLUE}--- Updating User Passwords ---${NC}"
    readarray -t allUsers < ${USERS}
    for user in "${allUsers[@]}"; do
        passwd --mindays 5 --warndays 7 --maxdays 60 ${user}
        usermod --password $(openssl passwd -1 ${PASSWORD}) ${user} 
    done

    readarray -t allAdmins < ${ADMINS}
    for admin in "${allAdmins[@]}"; do
        passwd --mindays 5 --warndays 7 --maxdays 14 ${admin}
        usermod --password $(openssl passwd -1 ${PASSWORD}) ${admin} 
    done
}

#============================================
# Update and Upgrade 
#============================================
# Update apt cache and upgrade
#  packages
#============================================
function updateAndUpgrade() {
    echo -e "${BLUE}--- Updating APT Packages ---${NC}"
    apt update -y
    apt upgrade -y
    rm -rf /var/lib/apt/lists/*
}

#============================================
# Install Packages
#============================================
# Installs some packages that I want
#  to have and some neccessary ones
#============================================
function installPackages() {
    echo -e "${BLUE}--- Installing APT Packages ---${NC}"
    apt install -y vim \
        htop \
        wget \
        net-tools
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
                                                          
    1. Run All <except plugins>

    -- Users --
    2. Remove Unapproved Users              3. Add Missing Users
    4. Remove Unapproved Sudoers            5. Add Missing Sudoers
    6. Add New Group

    -- Security --
    7. Setup Password Policy                8. Update User Passwords

    -- Software --
    9. Update and Upgrade                   10. Install packages

    -- Plugins --"

    offset=10
    count=$(( ${offset} + 1 ))
    for entry in "$(pwd)"/*sh; do
        entry=${entry#"$(pwd)/"}
        if [[ ${entry} == "CyberSecurity.sh" ]]; then
            continue
        fi

        echo "${count}. ${entry}"
        (( count++ ))
    done
    negOffset=$(( ${count} - ${offset} ))

    echo -e "${BLUE}
    -- Exit --
    ${count}. Exit
${NC}"

    read -r option

    if [[ $option == "1" ]]; then
        removeUnapprovedUsers
        addMissingUsers
        removeUnapprovedSudoers
        addMissingSudoers
        addGroup
        setupPasswordPolicy
        updatePasswords
        updateAndUpgrade
        installPackages
    elif [[ $option == "2" ]]; then
        removeUnapprovedUsers
    elif [[ $option == "3" ]]; then
        addMissingUsers
    elif [[ $option == "4" ]]; then
        removeUnapprovedSudoers
    elif [[ $option == "5" ]]; then
        addMissingSudoers
    elif [[ $option == "6" ]]; then
        addGroup
    elif [[ $option == "7" ]]; then
        setupPasswordPolicy
    elif [[ $option == "8" ]]; then
        updatePasswords
    elif [[ $option == "9" ]]; then
        updateAndUpgrade
    elif [[ $option == "10" ]]; then
        installPackages
    elif [[ $option -ge $(( ${count} - ${negOffset} )) && $option -lt $count ]]; then
        i=1
        for entry in "$(pwd)"/*sh; do
            entry=${entry#"$(pwd)/"}
            if [[ ${entry} == "CyberSecurity.sh" ]]; then
                continue
            fi

            if [[ $i == $(( $option - $offset )) ]]; then
                bash "./"${entry}
            fi
            (( i++ ))
        done
    elif [[ $option == "${count}" ]]; then
        exit
    fi
}

echo -e "${RED}--- DO THE FORESENSIC QUESTIONS FIRST --- DO THE FORENSIC QUESTIONS FIRST ----\n"
sleep 2
while true; do
   startScript 
   sleep 1
done
