#!/bin/bash

#Security Hydra
#Author: 3therk1ll

#"Security isn't a dirty word, Blackadder, crevice, is a dirty word."
#General Sir Anthony Cecil Hogmanay Melchett

#PROPS:
#www.top-hat-sec.com
#www.unix.com
#www.cyberciti.biz
#www.commandlinefu.com
#TAPEs Wordlist Manipulator. Referenced a few functions.

function set_variables() {


##########Text colours#############
STAND=$(tput sgr0)
RED=$(tput setaf 1)
REDB=$(tput setaf 1  && tput bold)
GRN=$(tput setaf 2)
YELL=$(tput setaf 3)
BLUE=$(tput setaf 4)
###################################

#Remote host to ping for network checks
#Default is OpenNIC DNS server
REMOTE_PING="78.138.97.33"

#Home directory
HOME_DIR="/root"

#Set superuser prefix if not running as root
SU_PFX=sudo

#Package installer
PKG="apt-get install"

#SSH 'Authorized Keys' Directory
AUTH_KEYFILE="$HOME_DIR/.ssh/authorized_keys"

#SSH Keys default bitsize. Recommend leave as default
SSH_KEY_BITSIZE=2048

#VPN Interface
VPN_IFACE="tun0"

check_installer
}

function initialise_and_set_main() {
clear
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo

echo $RED"	---- Checking network connections to determine NAT, disable this feature by commenting out the below line if working offline ----"$STAND

START_COUNT=0
START_COUNT=$(( $START_COUNT + 1 ))

#Script name
SCRIPT_NAME=$( $SU_PFX basename $0 )

#Script process ID
PID=$($SU_PFX pgrep $SCRIPT_NAME)

#Current user
USER_ID=$( $SU_PFX whoami )

# UTC time
UTC=$( $SU_PFX date -u )

#Local time
LOCAL=$( $SU_PFX date )

#Check for active network interface
read IFACE_CHECK <<< $( $SU_PFX ip route get $REMOTE_PING | awk 'NR==2 {print $1}' RS="dev" )
PATTERN='[ 0-9a-z ]'

if [[ $IFACE_CHECK =~ $PATTERN ]] ; then
	IFACE=$IFACE_CHECK
else
	IFACE=$RED"No Active Network Interface Found."$STAND
fi

#NAT address resolution
EXT_IP=$($SU_PFX curl http://ipecho.net/plain; echo ) ### <<< Disable here if working offline ### NAT Address

	case $EXT_IP in
		
		*.*.*.*)
		USER_EXT_IP=$EXT_IP
		GEOLOCATE_0=$( $SU_PFX geoiplookup $USER_EXT_IP | awk '{print $4}' ) #IP geolocation
		GEOLOCATE_1=$( echo "${GEOLOCATE_0%?}" )
		;;

		*)
		USER_EXT_IP=$RED"NAT ADDRESS UNAVAILABLE"$STAND
		COUNTRY=$RED"Gelocation Unavailable."$STAND
		;;

	esac	#End of NAT function

#LAN address resolution
USER_INT_IP=$( $SU_PFX /sbin/ifconfig $IFACE | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}' )

	case $USER_INT_IP in
		
		*.*.*.*)
		LAN_IP=$USER_INT_IP
		;;

		*)
		LAN_IP=$RED"LAN ADDRESS UNAVAILABLE"$STAND
		;;
	esac

#Set current directory
DIRECTORY=$($SU_PFX pwd)

#Set hostname
HOST=$($SU_PFX hostname)

#Check if root/superuser
if [ "$(id -u)" == "0" ] ; then
	IS_ROOT=$GRN"Privs OK"$STAND
else
	IS_ROOT=$RED"NOT RUNNING AS ROOT. SOME FEATURES REQUIRED SUPER USER PRIVILEGES."$STAND
fi

main_menu

}


function main_menu() {
clear
echo $RED"CODENAME: MELCHETT"$STAND
echo
echo $GRN"---- SECURITY HYDRA MAIN MENU ----"$STAND
echo
echo $YELL"-GENERAL SYSTEM/NETWORK INFORMATION-"$STAND
echo
echo "CURRENT USER:		$USER_ID $IS_ROOT"
echo "HOSTNAME:		$HOST"
echo "NAT ADDRESS: 		$USER_EXT_IP $GRN$GEOLOCATE_1$STAND $RED$GEO_IP_VACANT$STAND"
echo "LAN ADDRESS: 		$LAN_IP"
echo "NETWORK INTERFACE: 	$IFACE"
echo "CURRENT DIRECTORY:	$DIRECTORY"
echo "SCRIPT NAME: 		$SCRIPT_NAME"
echo "SCRIPT PID:		$PID"
echo "SYSTEM TIME- UTC:	$UTC"
echo "SYSTEM TIME- LOCAL:	$LOCAL"
echo "$FUNCTION_FAIL"
FUNCTION_FAIL=""
echo $YELL"		-OPTIONS-"$STAND
echo "1) Encrypt/Decrypt Files or Folders With Key or Passphrase."
echo "2) Verify Recieved Files- Requires Senders Public Key."
echo "3) Create and Distribute SSH Keys. 	$SSH_SERV_VACANT"
echo "4) Send Files via SSH. 			$SSH_SERV_VACANT"
echo "5) Secure Deletion.$RED ADVANCED USERS$STAND $SRM_VACANT"
echo "6) Set File Permissions."
echo "7) Password Utilities."
echo "8) System Information. 			$LMS_VACANT"
echo "9) Suspicious Script Checker."
echo
echo "'a' AFK VPN Leak Failsafe"
echo "'c' Config: Install Dependancies. $CONF"
echo "'d' Disk Utilities."
echo "'s' Checksum Comparison."
echo "'q' Quit."
echo
echo -ne $BLUE"Select Option: "$STAND

read MAIN_MENU

	case $MAIN_MENU in

		1)
		crypt_main
		;;

		2)
		verification
		;;

		3)
		SSH_REDIRECT=1
		ssh_server_start
		;;

		4)
		SSH_REDIRECT=2
		ssh_server_start
		;;

		5)
		deletion_main
		;;

		6)
		permissions
		;;

		7)
		password_utils
		;;

		8)
		sys_enum
		;;

		9)
		script_scan
		;;

		[aA])
		vpn_failsafe
		;;

		[cC])
		config_check
		;;

		[dD])
		disc_utilities_main
		;;

		[sS])
		checksum_compare
		;;

		[qQ])
		echo $GRN"Closing down..."$STAND
		sleep 1.5
		EX_CODE=$STAND"USER $GRN'$USER_ID'$STAND EXITED SCRIPT VIA MAIN MENU."
		clean_up_finish
		;;

		*)
		clear
		echo
		echo
		echo $RED"ERROR: Invalid Input"$STAND
		sleep 2
		main_menu
		;;

		"")
		echo
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		main_menu
		;;

	esac


}

function crypt_main() {
clear
echo
echo
echo "1) Encrypt/Decrypt Using Passphrase"
echo
echo "2) Encrypt/Decrypt Using Key"
echo
echo "Press 'q' Return To Main Menu"
echo
echo -ne $YELL"Select Option 1-3: "$STAND
read CRYPT_OPT

	case $CRYPT_OPT in

		1)
		crypt_pass
		;;

		2)
		crypt_key_options
		;;

		[qQ])
		main_menu
		;;

		*)
		echo $RED"Invalid Input"$STAND
		sleep 1
		crypt_main
		;;

	esac
}

function crypt_pass() {
clear
echo
echo
echo "1) Encrypt File"
echo
echo "2) Decrypt File"
echo
echo "3) Return To Previous Menu"
echo
echo -ne $YELL"Select Encrypt/Decrypt: "$STAND
read CRYPT_PASS_CHOICE

	case $CRYPT_PASS_CHOICE in

		1)
		encrypt_pass
		;;

		2)
		decrypt_pass
		;;

		3)
		crypt_main
		;;

		*)
		echo $RED"Invalid Input."$STAND
		sleep 2
		crypt_pass
		;;
	esac


}

function encrypt_pass() {
clear
echo
echo "Press 'q' to return"
echo
echo $GRN"Available Cipher Types:"$STAND
echo

echo 	"	aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb
	aes-256-cbc       aes-256-ecb       base64            bf
	bf-cbc            bf-cfb            bf-ecb            bf-ofb
	camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  camellia-192-ecb
	camellia-256-cbc  camellia-256-ecb  cast              cast-cbc
	cast5-cbc         cast5-cfb         cast5-ecb         cast5-ofb
	des               des-cbc           des-cfb           des-ecb
	des-ede           des-ede-cbc       des-ede-cfb       des-ede-ofb
	des-ede3          des-ede3-cbc      des-ede3-cfb      des-ede3-ofb
	des-ofb           des3              desx              rc2
	rc2-40-cbc        rc2-64-cbc        rc2-cbc           rc2-cfb
	rc2-ecb           rc2-ofb           rc4               rc4-40
	seed              seed-cbc          seed-cfb          seed-ecb
	seed-ofb          zlib"

echo
echo "To set default cipher types, edit this file in a text editor and permanently set the variable, 'E_CIPHER', to what you prefer."
echo
echo "Set encryption cipher type.$RED NOTE: YOU WILL NEED TO KNOW THIS TO DECRYPT$STAND "
echo
echo
##
echo -ne $GRN"Cipher Type: $STAND " ### Comment out this and next line if setting a default cipher type
read E_CIPHER
##

	case $E_CIPHER in

		[qQ])
		crypt_pass
		;;

		*)
		####
		#E_CIPHER="Define set cipher type here"
		#Do not forget to comment out 'read E_CIPHER' and echo -ne "Cipher type" above this.
		####
		echo -ne "Path to file to be encrypted: "
		read E_INFILE

			if $SU_PFX [ -a $KEYFILE_PATH ]; then
			echo $GRN"File found"$STAND
				else
			echo $RED"File not found."$STAND
			sleep 2
			encrypt_pass
			fi

		echo -ne "Encrypted filepath and name: "
		read E_OUTFILE

		echo
		echo $BLUE"Time to complete:"$STAND
		echo
		time $SU_PFX openssl $E_CIPHER -salt -a -e -in $E_INFILE -out $E_OUTFILE #encrypt

		echo -ne "Erase original plaintext file?$RED!!UNRECOVERABLE!!$STAND y/n: "
		read RM_ORIGIN

			case $RM_ORIGIN in

				[yY] | [yY][eE][sS])
					$SU_PFX srm -r $E_INFILE
					echo $GRN"Original shredded with default 3 passes"$STAND
					sleep 2
					;;

				[nN] | [nN][oO])
					echo $YELL"Returning to previous menu"$STAND
					sleep 1
					crypt_pass
					;;

			esac

		echo
		echo -ne "Press 'ENTER' To Return "
		read CONTINUE_OUT

			case $CONTINUE_OUT in

				*)
				crypt_pass
				;;
			esac


	esac

}

function decrypt_pass() {
clear
echo
echo "Press 'q' to return."
echo
echo $GRN"Available cipher types:"$STAND
echo

echo   "	aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb
	aes-256-cbc       aes-256-ecb       base64            bf
	bf-cbc            bf-cfb            bf-ecb            bf-ofb
	camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  camellia-192-ecb
	camellia-256-cbc  camellia-256-ecb  cast              cast-cbc
	cast5-cbc         cast5-cfb         cast5-ecb         cast5-ofb
	des               des-cbc           des-cfb           des-ecb
	des-ede           des-ede-cbc       des-ede-cfb       des-ede-ofb
	des-ede3          des-ede3-cbc      des-ede3-cfb      des-ede3-ofb
	des-ofb           des3              desx              rc2
	rc2-40-cbc        rc2-64-cbc        rc2-cbc           rc2-cfb
	rc2-ecb           rc2-ofb           rc4               rc4-40
	seed              seed-cbc          seed-cfb          seed-ecb
	seed-ofb          zlib"

echo
echo -ne $GRN"Set decryption cipher type:$STAND "
read D_CIPHER

	case $D_CIPHER in

		[qQ])
		crypt_pass
		;;

		*)
		echo
		echo -ne "Path to file to be decrypted: "
		read D_INFILE

		if $SU_PFX [ -a $D_INFILE ] ; then
		echo $GRN"File found"$STAND
			else
		echo $RED"File not found."$STAND
		sleep 2
		decrypt_pass
		fi

	echo
	echo -ne "Decrypted file path and name: "
	read D_OUTFILE
	echo
	echo $BLUE"Time to complete:"$STAND
	echo

	time $SU_PFX openssl $D_CIPHER -salt -a -d -in $D_INFILE -out $D_OUTFILE #decrypt

	echo $GRN"File decrypted"$STAND
	echo
	echo -ne "Any key to continue: "
	read CONTINUE_OUT

		case $CONTINUE_OUT in

			*)
			crypt_pass
			;;

		esac

		;;

	"")
	echo $RED"ERROR: Field must contain a value."$STAND
	sleep 2
	decrypt_pass
	;;

	esac

}

function crypt_key_options() {
clear
echo
echo "Press 'q' To Return"
echo
echo -ne $YELL"Create Key? y/n:$STAND "
read CREATION

	case $CREATION in

		[yY] | [yY][Ee][sS])
			create_enc_key
			;;

		[nN] | [Nn][Oo])
			enc_dec_opt
			;;

		[qQ])
		crypt_main
		;;

		*)
		echo $RED"Invalid Input."$STAND
		sleep 2
		crypt_key_options
		;;

	esac
}

function enc_dec_opt() {
clear
echo
echo
echo "1) Encrypt file"
echo
echo "2) Decrypt file"
echo
echo "Press 'q' to Return To Main Menu"
echo
echo -ne $YELL"Select Option: "$STAND
read ENC_DEC_CHOICE

	case $ENC_DEC_CHOICE in

		1)
		encrypt_key
		;;

		2)
		decrypt_key
		;;

		[qQ])
		main_menu
		;;

		*)
		echo $RED"Invalid Input."$STAND
		sleep 1
		enc_dec_opt
		;;

	esac

}

function create_enc_key() {
clear
echo

echo -ne $YELL"Specify key name:$STAND "
read KEYNAME

echo -ne $YELL"Specify key size, 1024, 2048, 4096:$STAND "
read KEYSIZE

clear
echo
echo $RED"Generating Private Key... "$STAND
echo
echo $BLUE"Time to complete:"$STAND
echo
time $SU_PFX openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$KEYSIZE -pkeyopt rsa_keygen_pubexp:3 -out priv-$KEYNAME.pem

echo
echo $RED"Private Key Created"$STAND
echo
$SU_PFX cat priv-$KEYNAME.pem

echo
echo $GRN"Generating Public Key"$STAND
echo
echo $BLUE"Time To Complete:"$STAND
echo
time $SU_PFX openssl pkey -in priv-$KEYNAME.pem -out pub-$KEYNAME.pem -pubout

echo
echo $GRN"Public Key Created"$STAND
echo
$SU_PFX cat pub-$KEYNAME.pem

echo
echo $BLUE"PUBLIC AND PRIVATE KEYS COMPLETE "$STAND
echo $YELL"Recommend you set permissions so that only you can view your private key. For shared systems."$STAND

set_perm_opt
}

function set_perm_opt() {

echo -ne $GRN"Set permissions? y/n: "$STAND
read PERM0

	case $PERM0 in

		[yY] | [yY][eE][sS])
			permissions
			;;

		[nN] | [nN][oO])
			enc_dec_opt
			;;

		*)
		echo $RED"Invalid Selection."$STAND
		sleep 2
		set_perm_opt
		;;
	esac
}

function encrypt_key() {
clear
echo
echo
echo -ne "List PUBLIC Keyfiles? y/n: "
read LIST_PUB
echo

	case $LIST_PUB in

		[yY] | [yY][eE][sS])
		echo $GRN"--- Available PUBLIC Keyfiles --- "$STAND
		echo
		$SU_PFX find / -name 'pub-*.pem' 2>/dev/null
		echo
		echo "---------------------------"
		echo
		;;

		[nN] | [nN][oO])
		echo
		;;

	esac
echo
echo -ne "Path/Name of$GRN PUBLIC$STAND key for encryption: "
read MY_PUB_KEY

	case $MY_PUB_KEY in

		[qQ])
		enc_dec_opt
		;;

		*)
		if $SU_PFX [ -a $KEYFILE_PATH ]; then
		echo $GRN"Key found"$STAND
			else
		echo $RED"Key not found."$STAND
		sleep 2
		encrypt_key
		fi
		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		encrypt_key
		;;
	esac

echo -ne "Path/Name of$RED PRIVATE$STAND key for digital verification: "
read MY_PRIV_KEY

	if $SU_PFX [ -a $MY_PRIV_KEY ]; then
	echo $GRN"Key found"$STAND
		else
	echo $RED"Key not found."$STAND
	sleep 2
	encrypt_key
	fi

echo -ne "Path/Name of plaintext file: "
read PLAINTEXT

	if $SU_PFX [ -a $PLAINTEXT ]; then
	echo $GRN"File found"$STAND
		else
	echo $RED"File not found."$STAND
	sleep 2
	encrypt_key
	fi

echo -ne "Path/Name for output ciphertext file: "
read ENCRYPTED

echo $BLUE"Default digital signature using sha256 created as $PLAINTEXT.signature.bin'"$STAND
echo
echo $BLUE"Time to complete:"$STAND
echo
time $SU_PFX openssl dgst -sha256 -sign $MY_PRIV_KEY -out $PLAINTEXT.signature.bin $PLAINTEXT
echo
echo $GRN"Digital verification file completed"$STAND
echo
echo $BLUE"Time to complete:"$STAND
echo
time $SU_PFX openssl pkeyutl -encrypt -in $PLAINTEXT -pubin -inkey $MY_PUB_KEY -out $ENCRYPTED.bin
echo $GRN"File ENCRYPTED as $BLUE $ENCRYPTED.bin"$STAND

encrypt_again_key

}

function encrypt_again_key() {

echo "Options"
echo
echo "1) Encrypt Another File"
echo
echo "Press 'q' to Return To Main Menu."
echo
echo -ne $YELL"Select Option:$STAND "
read ENCRYPT_EXIT

	case $ENCRYPT_EXIT in

		1)
		encrypt_key
		;;

		[qQ])
		main_menu
		;;

		*)
		encrypt_again_key
		;;

	esac
}

function decrypt_key() {
clear
echo
echo
echo -ne "List PRIVATE Keyfiles? y/n: "
read LIST_PRIV
echo

	case $LIST_PRIV in

	[yY] | [yY][eE][sS])

		echo "$RED------- Available PRIVATE Keyfiles -------"$STAND
		echo
		$SU_PFX find / -name 'priv-*.pem' 2>/dev/null
		echo
		echo "---------------------------"
		echo
		;;

	[nN] | [nN][oO])
		echo
		;;

		*)
		echo $RED"Invalid Selection."$STAND
		sleep 1
		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		decrypt_key
		;;

	esac
echo
echo "Press 'q' to return."
echo
echo -ne "Path to ciphertext binary file: "
read RX_CIPHER_BINARY

	case $RX_CIPHER_BINARY in

		[qQ])
		enc_dec_opt
		;;

		*)
		if $SU_PFX [ -a $RX_CIPHER_BINARY ] ; then
		echo $GRN"File found"$STAND
			else
		echo $RED"File not found."$STAND
		sleep 2
		decrypt_key
		fi
		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		decrypt_key
		;;

	esac

echo
echo -ne "Path To Private Key For Decryption: "
read MY_PRIV_KEY

	if $SU_PFX [ -a $MY_PRIV_KEY ] ; then
	echo $GRN"Key found"$STAND
		else
	echo $RED"Key not found."$STAND
	sleep 2
	decrypt_key
	fi

echo
echo -ne "Name/Path For Plaintext Output: "
read PLAIN_MSG
echo
echo $BLUE"Time To Complete:"$STAND
echo
time $SU_PFX openssl pkeyutl -decrypt -in $RX_CIPHER_BINARY -inkey $MY_PRIV_KEY -out $PLAIN_MSG
echo
echo "Decryption Complete"

echo "Options"
echo "e) Decrypt Another File"
echo
echo "Any Key To Return To Main Menu"
echo -ne $YELL"Select Option:$STAND "
read DECRYPT_EXIT

	case $DECRYPT_EXIT in

		[eE])
		decrypt_key
		;;

		*)
		main_menu
		;;

	esac
}

function verification() {
clear
echo
echo "Press 'q' to return."
echo
echo $RED"Ensure you have the sender public key and know what what digest was used by sender."$STAND
echo
echo $GRN"Recognised digests: md4, md5, rmd160, sha, sha1."$STAND
echo
echo -ne "Set digest: "
read SEND_DIGEST

	case $SEND_DIGEST in

		[qQ])
		main_menu
		;;

		[mM][dD][4] | [mM][dD][5] | [rR][mM][dD][160] | [sS][hH][aA] | [sS][hH][aA][1])
		echo
		echo -ne "Path to senders public key: "
		read SEND_PUBKEY

			if $SU_PFX [ -a $SEND_PUBKEY ] ; then
			echo $GRN"Senders public key found"$STAND
				else
			echo $RED"Senders public key not found."$STAND
			sleep 2
			verification
			fi

		echo -ne "Path to signature .bin file: "
		read SIGNATURE_BIN_FILE

			if $SU_PFX [ -a $SIGNATURE_BIN_FILE ] ; then
			echo $GRN"Signature .bin found"$STAND
				else
			echo $RED"Specified signature .bin not found."$STAND
			sleep 2
			verification
			fi

		echo -ne "Recieved message to verify: "
		read RX_MSG

			if $SU_PFX [ -a $RX_MSG ] ; then
			echo $GRN"Message file exists"$STAND
			echo
				else
			echo $RED"Message file does not exist."$STAND
			sleep 2
			verification
			fi

		echo $GRN"Verifying..."$STAND
		echo
		echo $BLUE"Time to complete:"$STAND
		echo
		time $SU_PFX openssl dgst -$SEND_DIGEST -verify $SEND_PUBKEY -signature $SIGNATURE_BIN_FILE $RX_MSG
		echo
		echo "Options"
		echo
		echo "1) Verify Another File"
		echo
		echo "Press 'ENTER' To Return To Main Menu"
		echo
		echo -ne "Select Option: "
		read VERIFY_EXIT

			case $VERIFY_EXIT in

				1)
				verification
				;;

				*)
				main_menu
				;;

			esac
		;;

		*)
		echo
		echo $RED"Input invalid. Check digest."$STAND
		sleep 2
		verification
		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		verification
		;;
	esac
}

function ssh_start() {
clear
echo
service ssh start
SSH_START_CHECK=$( echo $? )

	if [ $SSH_START_CHECK -eq 0 ] ; then
		echo $GRN"SSH STARTED SUCCESSFULLY"$STAND
		echo
	else
		echo
		echo $RED"SSH FAILED TO START"$STAND
		echo
	fi

if [ $SSH_REDIRECT -eq 1 ] ; then
				SSH_REDIRECT=0
				ssh_func_choice

			elif [ $SSH_REDIRECT -eq 2 ] ; then
				SSH_REDIRECT=0
				send_files

			fi
}

function ssh_func_choice() {
echo
echo "1) Create SSH keypair"
echo
echo "2) Distribute SSH keys"
echo
echo "3) Return To Main Menu"
echo
echo -ne $YELL"Enter option:$STAND "
read SSH_FORK

	case $SSH_FORK in

		1)
		ssh_func_create0
		;;

		2)
		ssh_func_list
		;;

		3)
		main_menu
		;;

		*)
		echo $RED"Invalid Selection."$STAND
		sleep 2
		ssh_func_choice
		;;
	esac
}

function ssh_func_create0() {
clear
echo
echo "Press 'q' to return to previous menu"
echo
echo "This function will create SSH keys and distribute public keys to specified remote/local hosts."
echo
echo "Default (recommended) bitsize for generated keys is 2048"
echo
echo $BLUE"Time to complete below:"$STAND
echo
time $SU_PFX ssh-keygen -t rsa -b $SSH_KEY_BITSIZE

echo
echo -ne "Press ENTER to continue."
read ENT_CONT

	case $ENT_CONT in

		[qQ])
		ssh_func_choice
		;;

		*)
		ssh_func_choice
		;;

	esac

}

function ssh_func_create1() {
clear
echo
echo
echo $GRN"Public And Private Keys Generated."$STAND
echo
echo $YELL"Recommend you set permissions so that only you can view your private key. For shared systems."$STAND
echo
echo -ne $GRN"Set Permissions? y/n:$STAND "
read PERM1

	case $PERM1 in
		[yY] | [yY][eE][sS])
			permissions
			;;

		[nN] | [Nn][oO])
			send_key_decision
			;;
	esac
}

function send_key_decision() {
clear
echo
			echo "Send PUBLIC Key To Remote/Local Host?"
			echo
			echo "'NO'- Return To Previous Menu"
			echo -ne "Enter y/n: "
			read SEND_CHOICE
				case $SEND_CHOICE in

					[yY])
					ssh_func_list
					;;

					[nN])
					ssh_func_choice
					;;

					*)
					echo $RED"Invalid Selection"$STAND
					sleep 2
					send_key_decision
					;;

				esac
}

function ssh_func_list() {
clear
echo
echo "Press 'q' to go back."
echo
echo -ne "List available keys? y/n: "
read LIST

	case $LIST in

		[yY] | [Yy][eE][sS])

		echo
		echo "----- Listing keyfiles on system created by this script -------"
		echo
		echo "$GRN------- Available PUBLIC keyfiles -------"$STAND
		echo
		$SU_PFX find / -name 'pub-*.pem' 2>/dev/null
		echo
		echo "---------------------------"
		echo
		echo "$RED------- Available PRIVATE Keyfiles -------"$STAND
		echo
		$SU_PFX find / -name 'priv-*.pem' 2>/dev/null
		echo
		echo "---------------------------"
		ssh_func_send0
		;;

	[nN] | [nN][oO])
		ssh_func_send0
		;;

		[qQ])
		ssh_func_choice
		;;

		*)
		echo $RED"Invalid input"$STAND
		;;
	esac

}
function ssh_func_send0() {
echo
echo "Press 'q' To Return."
echo
echo -ne "Path To Keyfile: "
read KEYFILE_PATH

	case $KEYFILE_PATH in

		[qQ])
		ssh_func_list
		;;

		*)
		if $SU_PFX [ -a $KEYFILE_PATH ]; then
			echo $GRN"FILE FOUND"$STAND
			echo
		else
			echo $RED"FILE NOT FOUND"$STAND
			sleep 2
			ssh_func_send0
		fi

	echo -ne "Remote/local HOST address. Example user@192.168.0.10: "
	read REMOTE_HOST_ADDR

		if $SU_PFX ping -c1 "$REMOTE_HOST_ADDR" > /dev/null; then
			echo "HOST is up"
			echo
		else
			echo $RED"Unable to reach host:$YELL$REMOTE_HOST_ADDR"$STAND
			sleep 2
			ssh_func_send0
		fi

	echo "Copying Key To Host $REMOTE_HOST..."
	$SU_PFX ssh-copy-id -i $KEYFILE_PATH $REMOTE_HOST_ADDR
	echo $GRN"Key Copied."$STAND
	echo

	echo -ne "Any Key To Continue: "
	read CONTINUE_OUT

		case $CONTINUE_OUT in

			*)
			ssh_func_choice
			;;
		esac

		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		ssh_func_send0
		;;

	esac

}

function send_files() {
#scp <file to upload> <username>@<hostname>:<destination path>
echo
echo $GRN"-- Send Files Over SSH --"$STAND
echo
echo "This utilises 'scp' and is better for smaller files."
echo "For larger files or remote administration, consider using 'sftp'"
echo
echo "1) Send File Over SSH"
echo
echo "2) Return To Main Menu"
echo
echo -ne "Select Option: "
read PROTOCOL
echo
echo -ne "File To Be Sent: "
read FILE_SEND

	if [ -a $FILE_SEND ] ; then
		echo $GRN"FILE FOUND"$STAND
		echo
	else
		echo $RED"FILE NOT FOUND."$STAND
		sleep 2
		send_files
	fi

echo
echo -ne "Remote Host Address: "
read ADDRESSEE

	if $SU_PFX ping -c 1 "$ADDRESSEE" > /dev/null ; then
		echo "Host '$ADDRESSEE'is up"
		echo
	else
		echo $RED"Unable To Reach Host:$YELL$ADDRESSEE"$STAND
		sleep 2
		send_files
	fi

echo -ne "Remote Host Username: "
read REMOTE_USENAME

echo -ne "Identity File: "
read ID_SEND

	if [ -a $ID_SEND ] ; then
		echo $GRN"FILE FOUND"$STAND
		echo
	else
		echo $RED"FILE NOT FOUND"$STAND
		sleep 2
		send_files
	fi

echo -ne "What port is ssh on?: "
read SSH_PORT

echo
echo -ne "Destination Path on Remote Host:"
read DEST_PATH
echo
	case $PROTOCOL in

		1)
		$SU_PFX scp -P $SSH_PORT -i $ID_SEND $REMOTE_USENAME@$ADDRESSEE:$DEST_PATH
		SSH_CHECK_SUCCESS=$( echo $? )
			if [ "$SSH_CHECK_SUCCESS" == "0" ] ; then
				echo
				echo $GRN"Operation completed successfully."$STAND
			else
				echo
				echo $RED"Something went wrong. Check error messages."$STAND
				echo
				echo "ENTER to continue."
				read SSH_FAIL_CONT

					case $SSH_FAIL_CONT in
						*)
						echo
						;;
					esac
			fi
		echo
		send_files
		;;

		2)
		main_menu
		;;

		*) echo $RED"Invalid Selection"$STAND
		sleep 2
		send_files
		;;
	esac

}

function deletion_main() {
clear
echo
echo $GRN"-- DELETION MAIN MENU --"$STAND
echo
echo "$FAIL_MESSAGE $DEL_FAIL"
echo
echo $RED"NOTE: SHREDDED FILES WILL BE PERMANENTLY DELETED!"$STAND
echo
echo "Log Wipe function uses the 'shred' and 'SRM' commands to securely erase specified files/logs/drives."
echo "Script will force permissions and files will be removed and securely overwritten."
echo
echo "Custom shred will securely erase specificaly defined files or folders."
echo
echo "1) Default File/Logs Wipe- Utilises SRM"
echo
echo "2) Custom File Deletion- Utilises SRM"
echo
echo "3) Drive Wipe- Utilises 'dd' with '/dev/random' and '/dev/zero'"
echo
echo "4) Wipe Large Files and Folders. Combines SHRED and SRM"
echo
echo "5) Cancel and Return To Main Menu"
echo
echo -ne $YELL"SELECT OPTION:$STAND "
read SHRED_OPT

	case $SHRED_OPT in

		1)
		default_wipe
		;;

		2)
		custom_wipe
		;;

		3)
		drive_kill
		;;

		4)
		large_wipe_0
		;;

		5)
		main_menu
		;;

		*)
		echo $RED"Invalid Selection"$STAND
		sleep 1.5
		deletion_main
		;;

	esac
}

function default_wipe() {
clear
echo
echo "Press 'q' to return."
echo
echo $GRN"Intended for relatively small files and folders, for larger ones use 'Custom Wipe'."$STAND
echo
echo $RED"Remove default files/directories and system logs with 38 passes..."$STAND
echo
echo "Using default settings will shred the following files/logs, plus any files added by user."
echo
echo $GRN"	srm -r $HOME_DIR/.bash_history
	srm -r /var/log/syslog
	srm -r /var/log/daemon.log
	srm -r /var/log/auth.log*
	srm -r /var/log/bootstrap.log
	srm -r /var/log/alternatives.log*
	srm -r /var/log/dpkg.log*
	srm -r /var/log/user.log
	srm -r /var/log/wtmp
	srm -r /var/log/lastlog
	srm -r /var/run/utmp
	srm -r /var/log/mail.*
	srm -r /var/log/syslog*
	srm -r /var/log/messages*
	srm -r /var/log/Xorg*
	srm -r /usr/share/sqlmap/output/*
	srm -r /var/log/cups/*
	srm -r /var/log/kern.log*
	srm -r /var/log/Xorg.0.log*
	srm -r /var/log/Xorg.1.log*"$STAND

echo
echo -ne "Continue? yes/no: "
read CONT_1

	case $CONT_1 in

		[yY] | [yY][Ee][Ss] )
			echo
			echo $RED"COMMENCING DELETION.THIS MAY TAKE SOME TIME DEPENDING ON AMOUNT OF DATA..."$STAND
			echo
			echo
			echo "Default wipe commented out by default..."
			sleep 5
			################################################################
			#srm -r $HOME_DIR/.bash_history
			#srm -r /var/log/syslog
			#srm -r /var/log/daemon.log
			#srm -r /var/log/auth.log*
			#srm -r /var/log/bootstrap.log
			#srm -r /var/log/alternatives.log*
			#srm -r /var/log/dpkg.log*
			#srm -r /var/log/user.log
			#srm -r /var/log/wtmp
			#srm -r /var/log/lastlog
			#srm -r /var/run/utmp
			#srm -r /var/log/mail.*
			#srm -r /var/log/syslog*
			#srm -r /var/log/messages*
			#srm -r /var/log/Xorg*
			#srm -r /usr/share/sqlmap/output/*
			#srm -r /var/log/cups/*
			#srm -r /var/log/kern.log*
			#srm -r /var/log/Xorg.0.log*
			#srm -r /var/log/Xorg.1.log*

			#srm -r /path/to/target #EXAMPLE
			#echo Use this feature for relatively smaller files and folders, for larger ones use "Custom Wipe"
			### ^^ ADD ADDITIONAL FILES/FOLDER HERE ^^ ###
			################################################################
			validate_delete
			echo
			;;

		[nN] | [nN][Oo] )
			echo $GRN"Cancelling and returning to previous menu."$STAND
			sleep 2
			deletion_main
			;;

		[qQ]) 
		deletion_main 
		;;

	esac
}

function custom_wipe() {
clear
echo
echo
echo $GRN"Press 'q' to return to previous menu:"$STAND
echo
echo -ne $BLUE"Set path/name to target files/directory: "$STAND
read TARGET

	if $SU_PFX [ -a $TARGET ] ; then
	echo
	echo $GRN"Target '$TARGET' found"$STAND
		else
	echo $RED"Target '$TARGET' not found."$STAND
	sleep 2
	deletion_main
	fi

	passes_number

}

function passes_number() {

echo
echo "$RED $TARGET $STAND will be permanently wiped/deleted."
echo
echo "Select deletion level: "
echo
echo "1) High- 38 passes, slower but more secure."
echo
echo "2) Low- 2  passes, faster but less secure."
echo
echo "Any key to return to previous menu"
echo
echo -ne "$YELL Select Option: "$STAND
read LEVEL0

	case $LEVEL0 in

		1)
		most_sec
		;;

		2)
		second_sec
		;;

		[qQ])
		deletion_main
		;;

		*)
		passes_number
		;;

	esac
}

function most_sec() {
clear
echo
echo $RED"$TARGET$STAND will be wiped with 38 passes- Most secure."
echo
echo -ne $RED"Continue with wipe? yes or no: "$STAND
read CONFIRM_DEL

	case $CONFIRM_DEL in
		[yY] | [yY][Ee][Ss] )
			echo
			echo $RED"COMMENCING WIPE. THIS MAY TAKE SOME TIME DEPENDING ON AMOUNT OF DATA..."$STAND
			echo
			echo $BLUE"Time to complete:"$STAND
			echo
			time $SU_PFX srm -dr $TARGET
			validate_delete
			;;

		[nN] | [nN][Oo] )
			echo
			echo $GRN"Cancelling and returning to last menu."$STAND
			sleep 1
			custom_wipe
			;;

		*)
		echo
		echo $RED"Invalid Selection."$STAND
		sleep 2
		most_sec
		;;
	esac
}

function second_sec() {
clear
echo
echo "$TARGET will be wiped with 2 passes- Faster but less secure."
echo
echo -ne $RED"Continue with wipe? yes or no:$STAND "
read CONFIRM_DEL_0

	case $CONFIRM_DEL_0 in

		[yY] | [yY][Ee][Ss] )
			echo
			echo $RED"COMMENCING WIPE. THIS MAY TAKE SOME TIME DEPENDING ON AMOUNT OF DATA..."$STAND
			echo
			echo
			echo $BLUE"Time to complete:"$STAND
			echo
			time $SU_PFX srm -drl $TARGET
			validate_delete
			;;

		[nN] | [nN][Oo] )
			echo
			echo $GRN"Cancelling and returning to last menu."$STAND
			sleep 1
			custom_wipe
			;;

		*)
		echo
		echo $RED"Invalid Selection. Returning to last menu."$STAND
		sleep 2
		second_sec
		;;

	esac
}

function drive_kill() {
clear
echo
echo $RED"Press 'q' to return to previous menu."$STAND
echo
echo "---------------------------$GRN AVAILABLE DISCS/DRIVES $STAND---------------------------"
echo
$SU_PFX df -h --sync -T -a
echo
echo "-------------------------------------------------------------------------------------"
$SU_PFX fdisk -l
echo
echo "-------------------------------------------------------------------------------------"
echo
echo -ne $BLUE"Drive or disc to target:$STAND "
read TGT_DRIVE

	case $TGT_DRIVE in

		[qQ])
		deletion_main
		;;

		*)
		echo
		echo "One pass in generally considered sufficient."
		echo
		echo -ne $BLUE"Number of passes- Less is faster:$STAND "
		read D_WIPE_PASS

			if [ $D_WIPE_PASS -eq 1 ] ; then
				AMOUNT="time"

			elif [ $D_WIPE_PASS -gt 1 ] ; then
				AMOUNT="times"
				COMP_TIME="Completion Time:"

			elif [ $D_WIPE_PASS == 0 ] ; then
				clear
				echo
				echo
				echo
				echo $REDB"ZERO IS NOT A VALID OPTION. MINIMUM 1 PASS REQUIRED."$STAND
				sleep 2
				drive_kill
			fi

		clear
		echo
		echo
		echo $YELL"Drive:'$TGT_DRIVE' will be overwritten with random data and zero's $D_WIPE_PASS $AMOUNT."$STAND
		echo
		echo $RED"!!!UNRECOVERABLE!!!"$STAND
		echo
		echo
		drive_wipe_exec
		;;

		"")
		echo
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		drive_kill
		;;
	esac

}

function drive_wipe_exec() {

echo -ne $RED"Continue? YES/NO:$STAND "
read DRIVE_WIPE_DEC

COUNTER_U_RAND=0 #counter for loop urandom
COUNTER_ZERO=0 #counter for loop zero
PASS_COUNT_1=1
PASS_COUNT_2=1

	case $DRIVE_WIPE_DEC in

		YES)
			echo
			echo $RED"Starting..."$STAND
			echo
			echo $YELL"Writing random data from '/dev/random' to: $RED'$TGT_DRIVE'"$STAND
			echo
				time while [ $COUNTER_U_RAND -lt $D_WIPE_PASS ]
					do
			echo "-------------------------------------------------------------------------------------"
			echo
			echo $BLUE"Process Info from /dev/random. Pass number: $PASS_COUNT_1 of $D_WIPE_PASS"$STAND
			echo

					$SU_PFX dd if=/dev/random of=$TGT_DRIVE bs=1M

						if [ $PASS_COUNT_1 -eq $D_WIPE_PASS ] ; then
						echo
						echo $BLUE"$COMP_TIME"$STAND
							else
						echo
						fi

					PASS_COUNT_1=$(( $PASS_COUNT_1 + 1 ))
					COUNTER_U_RAND=$(( $COUNTER_U_RAND + 1 ))
					echo

					done

			echo "-------------------------------------------------------------------------------------"
			echo
			echo $GRN"Random data written to '$RED$TGT_DRIVE'."$STAND
			echo
			echo $YELL"Overwriting drive '$RED$TGT_DRIVE$YELL' with zeros..."$STAND
			echo
				time while [ $COUNTER_ZERO -lt $D_WIPE_PASS ]
					do
			echo "-------------------------------------------------------------------------------------"
			echo
			echo $BLUE"Process Info from /dev/zero. Pass Number: $PASS_COUNT_2 of $D_WIPE_PASS"$STAND
			echo
					$SU_PFX dd if=/dev/zero of=$TGT_DRIVE bs=1M
					DRIVE_WRITE_SUCCESS=$( $SU_PFX echo $? )

						if [ $PASS_COUNT_2 -eq $D_WIPE_PASS ] ; then
						echo
						echo $BLUE"$COMP_TIME"$STAND
							else
						echo
						fi

					PASS_COUNT_2=$(( $PASS_COUNT_2 + 1 ))
					COUNTER_ZERO=$(( $COUNTER_ZERO + 1 ))

					echo

					done

			echo "-------------------------------------------------------------------------------------"
			echo
			if [ $DRIVE_WRITE_SUCCESS -eq 0 ] ; then
			echo $GRN"Drive Successfully Overwritten: '$YELL $TGT_DRIVE'"$STAND
			echo
			echo
			echo -ne $GRN"Reformat Drive? y/n:$STAND "
			read RETURN
				case $RETURN in

					[yY]) 
					disc_utilities_main 
					;;

					[nN])
					deletion_main
					;;

					*)
					echo $RED"Invalid Option"$STAND
					;;
				esac
			else
			echo $RED"Operation Failed."$STAND
			echo
			echo -ne "'ENTER' To Return To Deletion Main Menu."
			read FAILED_RETURN_TO_DEL_MAIN
				case $FAILED_RETURN_TO_DEL_MAIN in
					*)
					deletion_main
					;;
				esac
			fi
			;;

		NO)
			echo
			echo $RED"Operation Cancelled."$STAND
			echo
			echo "Start Again Or Return To Last Menu?"
			echo
			echo "1) Try Again."
			echo
			echo "2) Return To Deletion Menu."
			echo
			echo -ne $YELL"Select: $STAND"
			read RETURN

					case $RETURN in

						1)
						drive_kill
						;;

						2)
						deletion_main
						;;

						*)
						echo
						echo $RED"Invalid Option"$STAND
						drive_wipe_exec
						;;

					esac
			;;

		[nN] | [nN][oO] | [yY] | [yY][eE][sS])
		echo
		echo $YELL"Be explicit. Type 'YES' or 'NO' in full.$RED ALL UPPERCASE"$STAND
		echo
		sleep 1.5
		drive_wipe_exec
		;;

		*)
		echo
		echo $YELL"Invalid input. Type 'YES' or 'NO' only."$STAND
		echo
		sleep 2
		drive_wipe_exec
		;;

	esac

}

function large_wipe_0() {
clear
echo
echo $RED"Press 'q' to return to deletion menu."$STAND
echo
echo $YELL"This function uses both SHRED and SRM consecutively."
echo
echo "SHRED to recursively wipe the contents of files and SRM to do the same with directories inside."$STAND
echo
echo "USAGE: To delete entire contents show between * here: '$HOME_DIR/Desktop/*myfolder/folder1/folder2/secretstuff.txt*'"
echo "Set TARGET as: '$HOME_DIR/Desktop/myfolder/'"
echo "This will delete everything from 'myfolder' onwards."
echo
echo -ne $BLUE"Set number of PASSES for shred: "$STAND
read PASSES

	case $PASSES in

		[qQ])
		deletion_main
		;;

		[1-100]) 
		echo 
		;;

		"")
		echo
		echo $RED"This ERROR: Field must contain a value. Minumum 1 pass."$STAND
		sleep 2
		large_wipe_0
		;;

		[a-zA-Z]) 
		echo $RED"INTEGER REQUIRED."$STAND
		sleep 1
		large_wipe_0
		;;

	esac
echo
echo -ne $YELL"Set Target: "$STAND
read LARGE_TARGET

	case $LARGE_TARGET in
	
		[qQ])
		deletion_main
		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		large_wipe_0
		;;

		*)
		if $SU_PFX [ -a $LARGE_TARGET ] ; then
		echo
		echo $GRN"TARGET FOUND"$STAND
		echo
			else

		echo $RED"TARGET NOT FOUND."$STAND
		sleep 2
			large_wipe_0
		fi
		;;

	esac

large_wipe_1

}

function large_wipe_1() {

echo -ne $RED"Continue with delete? YES or NO: "$STAND
read CONFIRM_DEL_0

	case $CONFIRM_DEL_0 in

			YES)
			echo
			echo $RED"Recursively wiping directory contents..."$STAND
			echo
			echo $BLUE"Time to complete:"$STAND
			echo
			$SU_PFX time find $LARGE_TARGET -type f -exec shred -fuz -n $PASSES {} \;
			echo
			echo $RED"Recursively wiping directory and sub-directories..."$STAND
			echo
			echo $BLUE"Time to complete:"$STAND
			echo
			time srm -dr $LARGE_TARGET
			echo
			echo
			echo $GRN"DONE"$STAND
			echo
			validate_delete
			;;

			NO)
			echo $GRN"Cancelling and returning to last menu."$STAND
			sleep 1
			deletion_main
			;;

		*) 
		echo $RED"Invalid Selection. Enter YES or NO in uppercase."$STAND
		sleep 2
		large_wipe_1
		;;
	esac

}

function validate_delete() {
echo
echo $YELL"Confirming Deletion Of '$TARGET'..."$STAND
echo
	if [ ! -f $TARGET ] ; then
	echo
	echo $GRN"Files Securely Removed."$STAND
	echo
		else
	read FAIL_DATE <<< $( $SU_PFX date )

	FAIL_MESSAGE=$RED"PREVIOUS FAILED DELETION:"$STAND

	read DEL_FAIL <<< $( echo $RED"DELETION FAILED on $TARGET at $FAIL_DATE."$STAND )
	sleep 2
	fi

echo "$DEL_FAIL"
echo
echo -ne "Any Key To Continue: "
read CONTINUE_OUT

	case $CONTINUE_OUT in

		*)
		deletion_main
		;;
	esac

}


function permissions() {
clear
echo
echo "Press 'q' To Return."
echo
echo
read CURRENT <<< $( $SU_PFX whoami )
echo "You are currently logged in as:$GRN $CURRENT"$STAND
echo
echo -ne "Set File/Folder Path: "
read PATH

	case $PATH in

		[qQ])
		enc_dec_opt
		;;

		*)
		echo
		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		permissions
		;;
	esac

	if $SU_PFX [ -a $PATH ]; then
 	echo $GRN"File Found"$STAND
		else
  	echo $RED"File Not Found."$STAND
 	sleep 2
 	permissions
	fi

echo
echo -ne "Set USERNAME To Own File: "
read USERNAME

$SU_PFX chown $USERNAME $PATH
read FEEDBACK <<< $($SU_PFX ls -l $PATH)

echo
echo "$YELL $FEEDBACK"$STAND
echo
echo
echo "1) Specify Another Set Of Permissions"
echo
echo "2) Return To Main Menu"
echo
echo -ne "$YELL Enter Option: "$STAND
read PERMISSIONS_CHOICE

	case $PERMISSIONS_CHOICE in

		1) 
		permissions 
		;;

		2)
		main_menu
		;;
	esac
}

disc_utilities_main() {
clear
echo
echo $GRN"-- Disc Utilities And Formatting --"$STAND
echo
echo "'Press 'q' To Return To Main Menu."
echo
echo "1) Format A Drive"
echo
echo "2) Check Disc For Bad Blocks"
echo
echo "3) Disc Image Functions"
echo
echo -ne "Enter Option: "
read DISC_UTILS_CHOICE

	case $DISC_UTILS_CHOICE in

		1)
		drive_format
		;;

		2)
		BAD_BLOCK_CLEAR="clear"
		bad_block_assign_disc
		;;

		3)
		iso_functions
		;;

		[qQ])
		main_menu
		;;

		*)
		echo
		echo $RED"Invalid Option"$STAND
		sleep 1.5
		disc_utils_main
		;;

	esac

}

function drive_format() {
clear
echo
echo $GRN"------ Drive Format ------"$STAND
echo
echo "Press 'q' To Return To Previous Menu."
echo
echo $GRN"---- Available Formats ----"$STAND
echo
echo "1) FAT32 (vfat)"
echo
echo "2) Extended* File Systems (ext*)"
echo
echo "3)Journal File System (jfs)"
echo
echo "4) NTFS"
echo
echo "5) XFS"
echo
echo "6) ReiserFS"
echo
echo -ne "Enter Option: "
read DRIVE_FORM_OPT

	case $DRIVE_FORM_OPT in

		1)
		FORMAT_TYPE="vfat"
		;;

		2)
		clear
		echo
		echo $GRN"---- Extended File System (ext) ----"$STAND
		echo
		echo "Press 'q' To Return"
		echo
		echo "1) ext1"
		echo
		echo "2) ext2"
		echo
		echo "3) ext3"
		echo
		echo "4) ext4"
		echo
		echo -ne "Select 1-4: "
		read FORMAT_TARGET_EXT_OPT

			case $FORMAT_TARGET_EXT_OPT in

				1)
				FORMAT_TYPE="ext1"
				;;

				2)
				FORMAT_TYPE="ext2"
				;;

				3)
				FORMAT_TYPE="ext3"
				;;

				4)
				FORMAT_TYPE="ext4"
				;;

				[qQ])
				drive_format
				;;

				*)
				echo
				echo $RED"Invalid Option"$STAND
				sleep 1.5
				drive_format
				;;
			esac
		;;

		3)
		FORMAT_TYPE="jfs"
		;;

		4)
		FORMAT_TYPE="xfs"
		;;

		5)
		FORMAT_TYPE="reiserfs"
		;;

		[qQ])
		disc_utilities_main
		;;
		
		*)
		echo
		echo $RED"Invalid Option"$STAND
		sleep 1.5
		drive_format
		;;

	esac

format_device
}

function format_device() {
clear
echo
echo $GRN"			--------------------- Available Discs --------------------"$STAND
echo
$SU_PFX fdisk -l
echo
echo $GRN"				----------------------------------------"$STAND
echo
echo -ne "Select Device: "
read DEV_TGT

	if [ -b "$DEV_TGT" ] ; then
  		echo $GRN"DEVICE FOUND"$STAND
		echo
		echo "Automatically Check For Bad Blocks Post-Format? y/n: "
		read AUTO_CHECK
			case $AUTO_CHECK in

				[yY])
				AUTO_CHECK=$( bad_block_run )
				conduct_format
				;;

				[nN])
				AUTO_CHECK=""
				conduct_format
				;;

			esac
	else
		echo $RED"DEVICE NOT FOUND"$STAND
		sleep 1.5
		format_device
	fi

}

function conduct_format() {
clear
echo
echo $RED"Device '$DEV_TGT' will be formatted as '$FORMAT_TYPE'"$STAND
echo
echo -ne "Enter 'YES' To Continue Or 'NO' To Cancel And Return: "
read COND_FORM_DEC

	case $COND_FORM_DEC in

		YES)
		run_format
		;;

		NO)
		disc_utilities_main
		;;

		[nN] | [nN][oO] | [yY] | [yY][eE][sS])
		echo
		echo $YELL"Be explicit. Type 'YES' or 'NO' In Full.$RED ALL UPPERCASE"$STAND
		echo
		sleep 1.5
		conduct_format
		;;

		*)
		echo
		echo $RED"Invalid Input"$STAND
		sleep 1.5
		conduct_format
		;;

	esac
}

function run_format() {
clear
echo
echo $GRN"Formatting Now...."$STAND
echo
echo "Time To Complete Below"
echo
time $SU_PFX mkfs.$FORMAT_TYPE $DEV_TGT
FORMAT_SUCCESS=$( echo $? )

	if [ "$FORMAT_SUCCESS" == "0" ] ; then
		echo
		echo $GRN"Process Exited Successfully. Exit Code: $FORMAT_SUCCESS"
		BAD_BLOCK_CLEAR=""
		$AUTO_CHECK
	else
		echo
		echo $RED"Something Went Wrong. Check Error Messages."$STAND
	fi

echo
echo -ne "Press 'ENTER' To Continue"
read FORMAT_CONT

	case $FORMAT_CONT in
		*)
		disc_utilities_main
		;;
	esac
}

function bad_block_assign_disc() {
clear
echo
echo $GRN"			--------------------- Available Discs --------------------"$STAND
echo
$SU_PFX fdisk -l
echo
echo $GRN"				----------------------------------------"$STAND
echo
echo -ne "Select Device: "
read DEV_TGT
echo
	if [ -b "$DEV_TGT" ] ; then
  		echo $GRN"DEVICE FOUND"$STAND
		sleep 1.5
		bad_block_run
	else
		echo $RED"DEVICE NOT FOUND"$STAND
		sleep 1.5
		bad_block_assign_disc
	fi
}

function bad_block_run() {
$BAD_BLOCK_CLEAR
echo
echo $GRN"Checking For Bad Blocks Now..."$STAND
echo
echo "Time To Complete Below"
echo
time $SU_PFX badblocks -sv $DEV_TGT
BB_CHK_SUCCESS=$( echo $? )

	if [ "$BB_CHK_SUCCESS" == "0" ] ; then
		echo
		echo
		echo $GRN"Process Exited Successfully. Exit Code: $BB_CHK_SUCCESS"
	else
		echo
		echo
		echo $RED"Something Went Wrong. Check Error Messages."$STAND
	fi

echo
echo
echo -ne "Press 'ENTER' To Continue"
read FORMAT_CONT

	case $FORMAT_CONT in
		*)
		disc_utilities_main
		;;
	esac
}

function iso_functions() {
clear
echo
echo $GRN"--- ISO Image Functions ---"$STAND
echo
echo "Press 'q' To Return"
echo
echo "1) Copy ISO Image To Device"
echo
echo "2) Copy ISO Image From Device"
echo
echo "3) Checksum ISO Image"
echo
echo -ne "Enter Option: "
read ISO_OPT

	case $ISO_OPT in

		1)
		iso_to_device_prep
		;;

		2)
		device_to_iso_prep
		;;

		3)
		iso_checksums
		;;

		[qQ])
		disc_utilities_main
		;;

		*)
		echo
		echo $RED"Invalid Option"$STAND
		sleep 1.5
		iso_functions
		;;

	esac
}

function iso_to_device_prep() {
clear
echo
echo $GRN"--- Write ISO To Device ---"$STAND
echo
echo "Press 'q' To Return"
echo
echo -ne "Select ISO Image To Use: "
read ISO_TO_DEV_SELECT

	case $ISO_TO_DEV_SELECT in

		[qQ])
		iso_functions
		;;

		*)
		if [ -f $ISO_TO_DEV_SELECT ] ; then
			echo
			echo $GRN"FILE FOUND"$STAND
			echo
			select_device
		else
			echo
			echo $RED"FILE NOT FOUND"$STAND
			echo
			sleep 1.5
			iso_to_device_prep
		fi
		;;

	esac
}

function select_device() {
echo
echo
echo $GRN"			--------------------- Available Discs --------------------"$STAND
echo
$SU_PFX fdisk -l
echo
echo $GRN"				----------------------------------------"$STAND
echo
echo -ne "Select Device To Write To: "
read ISO_TO_DEV_TGT

	case $ISO_TO_DEV_TGT in

		[qQ])
		iso_functions
		;;

		*)
		if [ -b $ISO_TO_DEV_TGT ] ; then
			echo
			echo $GRN"DEVICE FOUND"$STAND
			echo
			iso_to_device_burn
		else
			echo
			echo $RED"DEVICE NOT FOUND"$STAND
			echo
			sleep 1.5
			select_device
		fi
		;;

	esac
}

function iso_to_device_burn() {
echo
echo $GRN"Copying '$ISO_TO_DEV_SELECT' to '$ISO_TO_DEV_TGT'"$STAND
echo
echo "Time To Complete Below"
echo
time $SU_PFX dd if=$ISO_TO_DEV_SELECT of=$ISO_TO_DEV_TGT
ISO_TO_DEV_CHECK=$( echo $? )

	if [ $ISO_TO_DEV_CHECK == 0 ] ; then
		echo
		echo
		echo $GRN"Process Exited Successfully. Exit Code: $ISO_TO_DEV_CHECK"
	else
		echo
		echo
		echo $RED"Something Went Wrong. Check Error Messages."$STAND
	fi
echo
echo -ne "Press 'ENTER' To Continue"
read ISO_TO_DEV_CONT

	case $ISO_TO_DEV_CONT in

		*)
		iso_functions
		;;

	esac
}

function device_to_iso_prep() {
clear
echo
echo $GRN"--- Write image From ISO To Device ---"$STAND
echo
echo "Press 'q' To Return"
echo
echo $GRN"			--------------------- Available Discs --------------------"$STAND
echo
$SU_PFX fdisk -l
echo
echo $GRN"				----------------------------------------"$STAND
echo
echo -ne "Select Device To Use: "
read DEV_TO_ISO_SELECT

	case $DEV_TO_ISO_SELECT in

		[qQ])
		iso_functions
		;;

		*)
		if [ -b $DEV_TO_ISO_SELECT ] ; then
			echo
			echo $GRN"DEVICE FOUND"$STAND
			echo
			echo -ne "Set Name For ISO Image: "
			read CREATE_ISO_NAME
			device_to_iso_burn
		else
			echo
			echo $RED"DEVICE NOT FOUND"$STAND
			echo
			sleep 1.5
			device_to_iso_prep
		fi
		;;

	esac
}

function device_to_iso_burn() {
echo
echo $GRN"Copying '$DEV_TO_ISO_SELECT' to '$CREATE_ISO_NAME'"$STAND
echo
echo "Time To Complete Below"
echo
time $SU_PFX dd if=$DEV_TO_ISO_SELECT of=$CREATE_ISO_NAME
DEV_TO_ISO_CHECK=$( echo $? )

	if [ "$DEV_TO_ISO_CHECK" == "0" ] ; then
		echo
		echo
		echo $GRN"Process Exited Successfully. Exit Code: $DEV_TO_ISO_CHECK"
	else
		echo
		echo
		echo $RED"Something Went Wrong. Check Error Messages."$STAND
	fi
echo
echo -ne "Press 'ENTER' To Continue"
read DEV_TO_ISO_CONT

	case $DEV_TO_ISO_CONT in

		*)
		iso_functions
		;;

	esac
}


function iso_checksums() {
clear
echo
echo $GRN"--- ISO CHECKSUM ---"$STAND
echo
echo "Press 'q' To Return"
echo
echo -ne "Select ISO Image: "
read ISO_CHECKSUM_SELECT

	case $ISO_CHECKSUM_SELECT in

		[qQ])
		iso_functions
		;;

		*)
		if [ -f $ISO_CHECKSUM_SELECT ] ; then
			echo
			echo $GRN"FILE FOUND"$STAND
			echo
			echo $GRN"Calculating Checksums..."$STAND
			echo
		else
			echo
			echo $RED"FILE NOT FOUND"$STAND
			echo
			sleep 1.5
			iso_checksums
		fi
		;;

	esac

MD5_SUM_ISO=$( $SU_PFX md5sum $ISO_CHECKSUM_SELECT | awk -F: '{print $0}' | awk '{print $1}' )
SHA1_SUM_ISO=$( $SU_PFX sha1sum $ISO_CHECKSUM_SELECT | awk -F: '{print $0}' | awk '{print $1}' )
SHA256_SUM_ISO=$( $SU_PFX sha256sum $ISO_CHECKSUM_SELECT | awk -F: '{print $0}' | awk '{print $1}' )

echo $GRN"--- CHECKSUMS ---"$STAND
echo
echo "MD5: $MD5_SUM_ISO"
echo
echo "SHA-1: $SHA1_SUM_ISO"
echo
echo "SHA-256: $SHA256_SUM_ISO"
echo
echo -ne "Press 'ENTER' To Return"
read ISO_CHECKSUM_RET

	case $ISO_CHECKSUM_RET in
		*)
		iso_functions
		;;
	esac
}

function password_utils() {
clear
echo $GRN"Password utilities available."$STAND
echo
echo "1) Hash a String."
echo
echo "2) Hash a Wordlist."
echo
echo "3) Create Password."
echo
echo "Press 'q' to Return To Main Menu."
echo
echo -ne $GRN"Select Option:$STAND "
read PASS_UTIL_OPT

	case $PASS_UTIL_OPT in

		1) 
		hasher_string 
		;;

		2) 
		hasher_file 
		;;

		3) 
		pass_gen0 
		;;

		[qQ]) 
		main_menu 
		;;

		*) 
		echo $RED"Invalid Input"$STAND
		sleep 1.5
		password_utils
		;;

	esac

}

function hasher_string() {
clear
echo
echo $RED"Press 'q' to return."$STAND
echo
echo "Digests: sha1 - sha256 - sha512 - md4 - md5"
echo
echo -ne $GRN"Select Digest Type:$STAND "
read HASH_TYPE_S

	case $HASH_TYPE_S in

		[qQ])
		password_utils
		;;

		*) 
		echo
		;;
	
	esac

echo -ne "Add salt at start of string? y/n: "
read SALT_S_Q

	case $SALT_S_Q in

		[nN]|[nN[oO])
			SALT_S="N/A"
			;;

		[yY]|[yY][eE][sS])
			echo $GRN"Enter salt:$STAND "
			read SALT_S
			;;

	esac

echo -ne $GRN"String:$STAND "
read HASH_STRING

	case $HASH_STRING in
		
		[qQ])
		password_utils
		;;

		*)
		read HASH_S <<< $( $SU_PFX echo -n $SALT_S$HASH_STRING | openssl $HASH_TYPE_S | cut -d' ' -f2 )
		echo
		echo $BLUE"Plaintext:$HASH_STRING$STAND "
		echo
		echo $BLUE"Hash:$HASH_S$STAND "
		echo
		echo $BLUE"Digest Type:$HASH_TYPE_S$STAND "
		echo
		echo $BLUE"Salt:$SALT "$STAND
		echo
		echo -ne $GRN"Run again? y/n:$STAND "
		read REPEAT
		
			case $REPEAT in
				
				[nN]|[nN][oO])
					password_utils
					;;

				[yY]|[yY][eE][sS])
					hasher_string
					;;

				*)
				echo $RED"Invalid Input"$STAND
				sleep 1.5
				hasher_string
				;;

			esac
		;;

	esac

}

function hasher_file() {
clear
echo
echo $RED"Press 'q' to return."$STAND
echo
echo "Digests: sha1 - sha256 - sha512 - md4 - md5"
echo
echo -ne "Select digest type: "
read HASH_TYPE_F

	case $HASH_TYPE_F in

		[qQ]) 
		password_utils 
		;;
	
		*) 
		echo
		;;
	
	esac
echo
echo -ne $GRN"Set outfile:$STAND "
read HASH_OUT
echo
echo -ne "Add salt at start of each string? y/n: "
read SALT_F_Q

	case $SALT_F_Q in

		[nN]|[nN[oO])
			SALT_F="N/A"
			;;

		[yY]|[yY][eE][sS])
			echo $GRN"Salt:$STAND "
			read SALT_F
			;;
	esac

echo -ne $GRN"Wordlist to be hashed:$STAND "
read WORDLIST

	case $WORDLIST in
		
		[qQ])
		password_utils
		;;

		*)
	
		while read line; do

			$SU_PFX echo -n $SALT_F$line | openssl $HASH_TYPE_F | cut -d' ' -f2

		done < $WORDLIST >> $HASH_OUT

		echo "Complete. Hash Another File? y/n: "
		read HASH_REP
			
			case $HASH_REP in
				
				[nN]|[nN][oO])
					password_utils
					;;

				[yY]|[yY][eE][sS])
					hasher_file
					;;

				*)
				echo $RED"Invalid Input"$STAND
				sleep 1.5
				hasher_file
				;;

			esac
		;;
	esac
}

function pass_gen0() {
clear
echo
echo "Press 'q' to return."
echo
echo $GRN"Random Password Generator"$STAND
echo
echo $RED"NOTE: PASSES WILL BE AUTOMATICALLY WRITTEN TO A FILE IN '/tmp' FOLDER."$STAND
echo $RED"OPTION TO DELETE FOLDER SECURELY WILL BE PRESENTED AFTER PASSES ARE GENERATED."$STAND
echo "Charsets: 0-9 a-z A-Z"
echo "Default Special Characters: ! @ # $ % ^ & + = - * < > £ "
echo

echo -ne "Password length:"
read PWD_LENGTH
echo
	case $PWD_LENGTH in
	
		[qQ]) 
		password_utils 
		;;

		*)
		echo
		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		pass_gen0
		;;

	esac

echo -ne "Number to generate:"
read PWD_NUMBER
echo
echo $GRN"$PWD_NUMBER passes of $PWD_LENGTH characters will be generated:"$STAND
echo

echo "Define Charsets"
echo
echo -ne "Use A-Z (Uppercase) y/n: "
read UPCASE_0
	case $UPCASE_0 in
		[yY])
		UPCASE_1=$(echo {A..Z})
		;;
		
		[nN])
		UPCASE_1=""
		;;
	esac
echo

echo -ne "Use a-z (Lowercase) y/n: "
read DOWNCASE_0
	case $DOWNCASE_0 in
		[yY])
		DOWNCASE_1=$(echo {a..z})
		;;
		
		[nN])
		DOWNCASE_1=""
		;;
	esac
echo

echo -ne "Numbers 0-9. y/n: "
read NUMBERS_0
	case $NUMBERS_0 in
		[yY])
		NUMBERS_1=$(echo {0..9})
		;;
		
		[nN])
		NUMBERS_1=""
		;;
	esac
echo


echo "Special characters: ! @ # $ % ^ \& + = - * > < £ "
echo -ne "Use Special Character? y/n: "
read SPECIALS_0
	case $SPECIALS_0 in
		[yY])
		#Add or remove special characters from array as required.
		declare -a SPECIALS_2=( \! \@ \# \$ \% \^ \& \+ \= \- \+ \> \< \£ )
		SPECIALS_3=$(echo ${SPECIALS_2[@]})
		;;
		
		[nN])
		SPECIALS_3=""
		;;
	esac
echo
		

echo -ne "Write passes to file? y/n: "
read WRITE_PASSES
echo

	case $WRITE_PASSES in

		[yY] | [yY][eE][sS])
			echo -ne $GRN"Set file name and path:$STAND "
			read OUTFILE
			echo
			FILE_OUT=1
			;;


		[nN] | [nN][oO])
			FILE_OUT=2
			echo $GRN"Passes will NOT be written to file."$STAND
			NA="N/A"
			echo
			;;
			
		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		pass_gen0
		;;

	esac

#Start of passgen loop
char=( $UPCASE_1 $DOWNCASE_1 $NUMBERS_1 $SPECIALS_3 )
			counter=0
			max=${#char[*]}
				if [ $FILE_OUT -eq 1 ] ; then
					touch $OUTFILE
				elif [ $FILE_OUT -eq 2 ] ; then
					echo
				fi

				while [ $counter -lt $PWD_NUMBER ]
					do
					out=""
				for i in `seq 1 $PWD_LENGTH`
					do
					let rand=${RANDOM}%${max}
					out="${out}${char[$rand]}"
				done
					counter=$(( $counter + 1 ))

				if [ $FILE_OUT -eq 1 ] ; then
					echo "$out" >> $OUTFILE
				elif [ $FILE_OUT -eq 2 ] ; then
					sleep 0.001
				fi

				echo "$out"
				done

			pass_gen1

}

function pass_gen1() {
echo
echo
echo "$YELL Options"$STAND
echo
echo "1) Run password generator again"
echo
echo "2) Return To Main Menu"
echo
echo "3) Shred passfile written to:$RED $OUTFILE $NA "$STAND
echo
echo -ne "Select Option 1-3: "
read PASS_GEN_CHOICE

	case $PASS_GEN_CHOICE in

		1)
		pass_gen0
		;;

		2)
		main_menu
		;;

		3)
		shred_outfile
		;;

		*)
		echo
		echo $RED"Invalid selection."$STAND
		echo
		pass_gen1
		;;

		"")
		echo $RED"ERROR: Field must contain a value."$STAND
		sleep 2
		pass_gen1
		;;

	esac
echo
echo
}

function shred_outfile() {
trap delete_cancel SIGINT
echo
echo
echo $RED"Deleting File:$YELL'$OUTFILE'$RED In 5 Seconds. Ctrl+C To Cancel..."$STAND
sleep 5
echo $RED"Deleting...."$STAND
echo
echo $BLUE"Time To Complete:"$STAND
echo
time $SU_PFX shred -fuzn 7 $OUTFILE

	if [ ! -f $OUTFILE ] ; then
	echo
	echo $GRN"$OUTFILE Deleted."$STAND
	sleep 2
		else
	echo
	read OUTFILE_FAIL_DATE <<< $( $SU_PFX date )

	FUNCTION_FAIL=$RED"Deletion of $YELL$OUTFILE$RED failed at $GRN$OUTFILE_FAIL_DATE.$RED Try again manually."$STAND

	sleep 2
	main_menu

	fi

echo
echo -ne "Any key to continue: "
read CONTINUE_OUT

	case $CONTINUE_OUT in

		*)
		main_menu
		;;

	esac
}

function delete_cancel() {
clear
echo
echo $GRN"Deletion Of '$OUTFILE' Cancelled By:$STAND $USER_ID"
echo
echo -ne "Press 'ENTER' To Continue..."
read DEL_CAN_ACK
	case $DEL_CAN_ACK in
		*)
		deletion_main
		;;
	esac
}

function sys_enum() {
clear
read EXT_IP2 <<< $($SU_PFX curl http://ipecho.net/plain ; echo > /dev/null 2>&1)
clear
echo "				$RED++++ SYSTEM NETWORK AND HARDWARE ENUMERATION ++++"$STAND
echo
echo $BLUE"++++ GENERAL ++++"$STAND
echo
echo
HNAME=$( $SU_PFX hostname )
echo $GRN"HOSTNAME:$STAND $HNAME"
echo

USENAME=$( $SU_PFX whoami )
echo $GRN"USERNAME:$STAND $USENAME"
echo

OS=$( $SU_PFX uname -o )
echo $GRN"OPERATING SYSTEM TYPE:$STAND $OS"
echo

L_TIME=$( $SU_PFX date )
echo $GRN"LOCAL TIME:$STAND $L_TIME"
echo

UTC_TIME=$( $SU_PFX date -u )
echo $GRN"UNIVERSAL COORDINATED TIME (UTC):$STAND $UTC_TIME"$STAND
echo

RUNLEVEL=$( $SU_PFX runlevel )
echo $GRN"CURRENT RUNLEVEL:$STAND $RUNLEVEL"
echo

UPTIME=$( $SU_PFX uptime | grep "up" | awk -F: '{print $0}' | awk '{print $3}' )
UPTIME_CUT=$( $SU_PFX echo "${UPTIME%?}" )
echo $GRN"SYSTEM UPTIME:$STAND $UPTIME_CUT hrs"
echo

read CUR_IFACE <<< $( $SU_PFX ip route get $REMOTE_PING | awk 'NR==2 {print $1}' RS="dev" )
echo $GRN"CURRENT NETWORK INTERFACE:$STAND $CUR_IFACE"
echo

read MAC <<< $( $SU_PFX macchanger -s wlan1 | grep "Current" | awk -F: '{print $0}' | awk '{print $3}' )
echo $GRN"CURRENT INTERFACE MAC:$STAND $MAC"
echo

read INT_IP <<< $( $SU_PFX /sbin/ifconfig $CUR_IFACE | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}' )
echo $GRN"LAN ADDRESS:$STAND $INT_IP"
echo

#read EXT_IP2 <<< $($SU_PFX curl http://ipecho.net/plain ; echo > /dev/null 2>&1) #Runs at top of function
	
	case $EXT_IP2 in

		*.*.*.*)
			echo $GRN"NAT ADDRESS:$STAND $EXT_IP2"
			echo
			echo
			;;

		*)
		echo
		echo $RED"NAT ADDRESS: UNAVAILABLE"$STAND
		echo
		echo
		;;
	esac

echo "				$RED++++ MACHINE HARDWARE INFORMATION ++++$STAND"
echo
KERN_NAME=$( $SU_PFX uname -s )
echo $GRN"KERNEL NAME:$STAND $KERN_NAME"$STAND
echo

KERN_REL=$( $SU_PFX uname -r )
echo $GRN"KERNEL RELEASE:$STAND $KERN_REL"$STAND
echo

KERN_VERS=$($SU_PFX uname -v)
echo $GRN"KERNEL VERSION:$STAND $KERN_VERS"$STAND
echo

ARCH=$( $SU_PFX uname -m )
echo $GRN"SYSTEM ARCHITECTURE:$STAND $ARCH"$STAND
echo

NET_NODE_HOSTNAME=$( $SU_PFX uname -n )
echo $GRN"NETWORK NODE HOSTNAME:$STAND $NET_NODE_HOSTNAME"$STAND
echo

HARD_PLAT=$( $SU_PFX uname -i )
echo $GRN"HARDWARE PLATFORM:$STAND $HARD_PLAT"$STAND
echo
echo


echo 				$RED"++++ CPU INFO ++++"$STAND
echo
echo
read CPU_VENDOR_ID <<< $( $SU_PFX cat /proc/cpuinfo | grep "vendor_id" | awk -F: '{print $2}' | uniq )
echo $GRN"CPU VENDOR ID:$STAND $CPU_VENDOR_ID"
echo
read CPU_MODEL <<< $( $SU_PFX cat /proc/cpuinfo | grep "model name" | awk -F: '{print $2}'| uniq )
echo $GRN"CPU MODEL:$STAND $CPU_MODEL"
echo
read CORE_NO <<< $( $SU_PFX cat /proc/cpuinfo | grep "cpu cores" | awk -F: '{print $2}'| uniq )
echo $GRN"NUMBER OF CORES:$STAND $CORE_NO"
echo
read MHZ <<< $( $SU_PFX cat /proc/cpuinfo | grep "cpu MHz" | awk -F: '{print $2}'| uniq )
echo $GRN"CPU MHz:$STAND $MHZ"
echo

echo $GRN"++ CPU TEMPERATURES ++"$STAND
echo
CURRENT=$( $SU_PFX sensors -A | grep temp1 | awk -F: '{print $2}' | awk '{print $1}' )
echo $RED"CURRENT OPERATING:$STAND $CURRENT"
echo
HIGH_0=$( $SU_PFX sensors -A | grep high | awk -F: '{print $2}' | awk '{print $4}' )
echo $RED"HIGHEST OPERATING:$STAND $HIGH_1"
echo
HYST_0=$( $SU_PFX sensors -A | grep "hyst" | awk -F: '{print $1}' | awk '{print $6}' )
HYST_1=$( echo ${HYST_0%?})
echo $RED"HYSTERICAL:$STAND $HYST_1"
echo
CRIT=$( $SU_PFX sensors -A | grep crit | awk -F: '{print $1}' | awk '{print $3}' )
echo $RED"CRITICAL:$STAND $CRIT"

echo
read CPU_FAM <<< $($SU_PFX cat /proc/cpuinfo | grep "cpu family" | awk -F: '{print $2}'| uniq )
echo $GRN"CPU FAMILY:$STAND $CPU_FAM"
echo
read CACHE <<< $($SU_PFX cat /proc/cpuinfo | grep "cache size" | awk -F: '{print $2}'| uniq )
echo $GRN"CPU CACHE SIZE:$STAND $CACHE"
echo
read MICROCODE <<< $($SU_PFX cat /proc/cpuinfo | grep "microcode" | awk -F: '{print $2}'| uniq )
echo $GRN"CPU MICROCODE:$STAND $MICROCODE"
echo
echo $GRN"CPU USAGE. 10 HEAVIEST LOADS AND PARENT COMMANDS"$STAND
echo
echo $YELL"FIELD, 'COMMAND', LENGTHS TRIMMED TO 140 CHARACTERS."$STAND
echo
$SU_PFX ps -eo pcpu,pid,user,args | sort -r -k1 | head -10 | cut -c 1-140
echo
echo

echo "				$RED++++ GRAPHICS PROCESSING UNIT (GPU) ++++"$STAND
echo
echo $GRN"GPU:"$STAND
read GPU_H <<< $($SU_PFX lspci -v -s `lspci | awk '/VGA/{print $1}'` | head -1 )
GPU_T=$($SU_PFX lspci -v -s `lspci | awk '/VGA/{print $1}'` | tail -2 | awk '{print $5}' )
echo "$GPU_H"
echo
echo $GRN"KERNEL DRIVER IN USE: $STAND$GPU_T"
echo
echo

echo "			$RED++++ RAM AND DISC USAGE AND CONNECTED USB DEVICES ++++"$STAND

echo $GRN"RAM INFO"$STAND
echo
$SU_PFX free -th
echo

echo $GRN"DRIVES AND DISC USAGE"$STAND
echo
$SU_PFX df -h --sync -T -a
echo

echo $GRN"DISC PARTITIONS"$STAND
echo
$SU_PFX blkid
echo

echo $GRN"INODES USAGE"$STAND
echo
$SU_PFX df -i
echo

echo
echo $GRN"USB DEVICES"$STAND
echo
$SU_PFX lsusb
echo
echo

echo "				$RED++++ LANGUAGE VERSIONS ++++"$STAND
echo
echo $GRN"Python:"$STAND
$SU_PFX python --version
echo

GCC=$($SU_PFX gcc --version | grep gcc | awk -F: '{print $1}')
echo $GRN"GCC (GNU C Compiler):"$STAND
echo "$GCC"
echo

RUBY=$($SU_PFX ruby --version)
echo $GRN"Ruby:$STAND $RUBY"
echo

PERL=$($SU_PFX perl --version | grep "perl" | head -n 2)
echo $GRN"Perl:$STAND $PERL"
echo

echo $GRN"Java:"$STAND
$SU_PFX java -version
echo
echo

echo $GRN"PHP:"$STAND
$SU_PFX php --version | head -n 1
echo
echo


echo "				$RED++++ NETWORK INFORMATION ++++"$STAND
echo
echo $GRN"ROUTING TABLE"$STAND
echo
$SU_PFX netstat -r
echo

echo $GRN"INTERFACE TABLE"$STAND
echo
$SU_PFX netstat -i
echo

echo $GRN"IP GROUP MEMBERSHIPS"$STAND
echo
$SU_PFX netstat -g
echo
echo


echo "			$RED+++ KERNEL DRIVERS INFORMATION +++"$STAND
echo
echo $GRN"KERNEL DRIVERS"$STAND
echo
echo $RED"LARGE OUTPUT. COMMENTED OUT. UNCOMMENT TO USE."$STAND
#$SU_PFX lspci -k
echo

echo $GRN"KERNEL DRIVERS TREE"$STAND
echo
echo $RED"LARGE OUTPUT. COMMENTED OUT. UNCOMMENT TO USE."$STAND
#$SU_PFX lspci -tv
echo

echo $GRN"KERNEL MODULES"$STAND
echo
echo $RED"LARGE OUTPUT. COMMENTED OUT. UNCOMMENT TO USE."$STAND
#$SU_PFX lsmod
echo


echo $GRN"NETWORKING STATISTICS"$STAND
echo
echo $RED"LARGE OUTPUT. COMMENTED OUT. UNCOMMENT TO USE."$STAND
#$SU_PFX netstat -s
echo

echo -ne $YELL"Press 'ENTER' to Return To Main Menu."$STAND
read SYS_ENUM_RET

	case $SYS_ENUM_RET in

		*)
		main_menu
		;;

	esac
}

function script_scan() {
clear
clear
echo
echo "Press 'q' to Return To Main Menu."
echo
echo $GRN"+++ SUSPICIOUS SCRIPT CHECKER +++"$STAND
echo
echo "Note: Designed to check for *nix shell commands such as in Bash."
echo "Only effective with languages such as Python, C etc if they are running shell commands."
echo
echo $YELL"See 'http://ubuntuguide.org/wiki/Malicious_Linux_Commands' for explaination of commands."$STAND
echo
echo -ne "Path to script to be scanned: "
read SUSP_FILE

	case $SUSP_FILE in

		[qQ])
		main_menu
		;;

		*)
		if [ -a $SUSP_FILE ] ; then
			echo
			echo $GRN"FILE FOUND"$STAND
			echo
			echo $GRN"Starting checks..."$STAND
			sleep 1.5
		else
			echo
			echo $RED"FILE NOT FOUND. CHECK PATH"$STAND
			sleep 1.5
			script_scan
		fi
		;;

	esac

	#Is file executable?
	if [[ -x "$SUSP_FILE" ]] ; then

    		EXECUTABLE="YES"
	else

   		 EXECUTABLE="NO"
	fi

	#File type
	if [ ${SUSP_FILE: -4} == ".txt" ] ; then
	D_TYPE="Text document"

	elif [ ${SUSP_FILE: -4} == ".doc" ] ; then
		D_TYPE="Word Doc format"

	elif [ ${SUSP_FILE: -3} == ".sh" ] ; then
		D_TYPE="Shell script"

	elif [ ${SUSP_FILE: -3} == ".rb" ] ; then
		D_TYPE="Ruby script"

	elif [ ${SUSP_FILE: -3} == ".py" ] ; then
		TYPE="Python script"

	elif [ ${SUSP_FILE: -3} == ".pl" ] ; then
		D_TYPE="Perl script"

	elif [ ${SUSP_FILE: -2} == ".c" ] ; then
		D_TYPE="C script"

	elif [ ${SUSP_FILE: -4} == ".cpp" ] ; then
		D_TYPE="C++ script"

	elif [ ${SUSP_FILE: -5} == ".java" ] ; then
		D_TYPE="Java script"

	elif [ ${SUSP_FILE: -3} == ".js" ] ; then
		D_TYPE="Javascript script"

	elif [ ${SUSP_FILE: -4} == ".sql" ] ; then
		D_TYPE="SQL file"

	else
	D_TYPE="UNKNOWN TYPE"

	fi

#Type of file
TYPE=$( $SU_PFX stat -c%F $SUSP_FILE )

#Size in bytes
BYTES=$( $SU_PFX stat -c%s $SUSP_FILE )

#Access rights in octal
ACCESS_RIGHTS_0=$( $SU_PFX stat -c%a $SUSP_FILE )

#Access rights human readable
ACCESS_RIGHTS_1=$( $SU_PFX stat -c%A $SUSP_FILE )

#MD5, SHA1 and SHA256 sums
MD5_SUM=$( $SU_PFX md5sum $SUSP_FILE | awk -F: '{print $0}' | awk '{print $1}' )
SHA1_SUM=$( $SU_PFX sha1sum $SUSP_FILE | awk -F: '{print $0}' | awk '{print $1}' )
SHA256_SUM=$( $SU_PFX sha256sum $SUSP_FILE | awk -F: '{print $0}' | awk '{print $1}' )

echo
echo $YELL"++ MISCELLANEOUS FILE INFO ++"$STAND
echo
echo $GRN"Is Executable:$STAND $EXECUTABLE"
echo
echo $GRN"Access Rights:$STAND $ACCESS_RIGHTS_0 or $ACCESS_RIGHTS_1"
echo
echo $GRN"Document Type:$STAND $D_TYPE"
echo
echo $GRN"File Type:$STAND $TYPE"
echo
echo $GRN"File Size In Bytes:$STAND $BYTES"
echo
echo $YELL"++ CHECKSUMS ++"$STAND
echo
echo $GRN"MD5:$STAND $MD5_SUM"
echo
echo $GRN"SHA-1:$STAND $SHA1_SUM"
echo
echo $GRN"SHA-256:$STAND $SHA256_SUM"
echo
echo $YELL"++++++++++++++++"$STAND
echo
echo $RED"++ DANGEROUS COMMANDS CHECK ++"$STAND
RESULTS=0
#Erases a directory
echo
echo $BLUE"Checking for 'rm -rf' command..."$STAND
SUSP_STR="rm -rf"

	if 
	$SU_PFX grep "$SUSP_STR" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_1=$( $SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$SUSP_STR" $SUSP_FILE )
		echo $RED"DANGEROUS COMMAND: 'rm -rf' FOUND on line: $LINE_1_a"$STAND
		echo "EXAMPLE:'rm -rf' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
	else
	echo $GRN"Command 'rm -rf' command not found."$STAND
	echo
	fi

#Python version of 'rm -rf'
echo
echo $BLUE"Checking for Python version of 'rm -rf' command..."$STAND
PY_RM="python -c 'import os; os.system"

	if 
	$SU_PFX grep "$PY_RM" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_2=$( $SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$PY_RM" $SUSP_FILE )
		echo $RED"Possible DANGEROUS COMMAND: 'rm -rf' in Python FOUND on line: $LINE_2"$STAND
		echo "EXAMPLE:'python -c 'import os; os.system("".join([chr(ord(i)-1) for i in "sn!.sg!+"]))'' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Command variant in Python of 'rm -rf' command not found."$STAND
	echo
	fi

#Fork bomb
echo $BLUE"Checking for Fork Bomb..."$STAND
FORK_BOMB="\:\(\){ :\|\: \& \}\;\:"

	if
	$SU_PFX grep "$FORK_BOMB" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_3=$( $SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$FORK_BOMB" $SUSP_FILE )
		echo $RED"DANGEROUS COMMAND: 'Fork Bomb' FOUND on line: $LINE_3"$STAND
		echo "EXAMPLE:':(){ :|: & };:' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Fork Bomb not found."$STAND
	echo
	fi

#Fork bomb in Perl
echo
echo $BLUE"Checking for Fork Bomb in Perl..."$STAND
PERL_FORK="fork then fork"

	if
	$SU_PFX grep "$PERL_FORK" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_4=$( $SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$PERL_FORK" $SUSP_FILE )
		echo $RED"DANGEROUS COMMAND: 'Perl Fork Bomb' FOUND on line: $LINE_4"$STAND
		echo "EXAMPLE:'fork while fork' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Perl Fork Bomb not found."$STAND
	echo
	fi

echo
echo $BLUE"Checking for possible reformatting..."$STAND
REFORMAT="mkfs"

	if
	$SU_PFX grep "$REFORMAT" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_5=$( $SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$REFORMAT" $SUSP_FILE )
		echo $RED"DANGEROUS COMMAND: Possible disc reformat FOUND on line: $LINE_5"$STAND
		echo "EXAMPLE:'mkfs # mkfs.ext3' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Reformat command not found."$STAND
	echo
	fi

#Write command to hard drive
echo
echo $BLUE"Checking for possible drive overwrite..."$STAND
OVW_DRIVE="> /dev/sda"

	if
	$SU_PFX grep "$OVW_DRIVE" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_6=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$OVW_DRIVE" $SUSP_FILE)
		echo $RED"DANGEROUS COMMAND: Possible drive overwrite FOUND on line: $LINE_6"$STAND
		echo "EXAMPLE:' 'a_command > /dev/sda*' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Drive overwrite command not found."$STAND
	echo
	fi

#Overwrite random data to drive
echo
echo $BLUE"Checking for possible drive overwrite..."$STAND
RAND_TO_SDA="dd if=/dev/random of=/dev/sda"

	if
	$SU_PFX grep "$RAND_TO_SDA" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_7=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$RAND_TO_SDA" $SUSP_FILE)
		echo $RED"DANGEROUS COMMAND: Possible random data drive overwrite FOUND on line: $LINE_7"$STAND
		echo "EXAMPLE:'dd if=/dev/random of=/dev/sda*' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Drive random data overwrite command not found."$STAND
	echo
	fi

#Moves an object to black hole
echo
echo $BLUE"Checking for objects being moved to /dev/null. Black hole."$STAND
BLACK_HOLE="> /dev/null"

	if
	$SU_PFX grep "$BLACK_HOLE" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_8=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$BLACK_HOLE" $SUSP_FILE)
		echo $RED"DANGEROUS COMMAND: Possible move of object/directory to '/dev/null' FOUND on line: $LINE_8"$STAND
		echo "EXAMPLE:'mv 'a_file_or_folder' > /dev/null' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Object/directory move to /dev/null not found."$STAND
	echo
	fi

#wget and curl fetching scripts
echo $BLUE"Checking for wget or curl. Some scripts may fetch and run other malicious scripts using wget or curl."$STAND
WGET="wget"

	if
	$SU_PFX grep "$WGET" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_9=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$WGET" $SUSP_FILE)
		echo $RED"DANGEROUS COMMAND: 'wget' FOUND on line: $LINE_9"$STAND
		echo "EXAMPLE:'wget a_url -O – | a_script.sh' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"wget not found."$STAND
	echo
	fi

echo
CURL="curl"

	if
	$SU_PFX grep "$CURL" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_10=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$CURL" $SUSP_FILE)
		echo $RED"DANGEROUS COMMAND: 'curl' FOUND on line: $LINE_10"$STAND
		echo $"EXAMPLE:'curl a_url -O – | a_script.sh' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"curl not found."$STAND
	echo
	fi

#Executes another script
echo
echo $BLUE"Checking for script execution."$STAND
EXECUTES="sh ./"

	if
	$SU_PFX grep "$EXECUTES" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_11=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$EXECUTES" $SUSP_FILE)
		echo $RED"DANGEROUS COMMAND: Possible script execution FOUND on line: $LINE_11"$STAND
		echo "EXAMPLE:'sh ./' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Script execution not found."$STAND
	echo
	fi

#telinit/init runlevel changes
echo
echo $BLUE"Checking for changes to runlevels."$STAND
TELINIT="telinit"
INIT="init"

	if
	$SU_PFX grep "$TELINIT" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_12=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$TELINIT" $SUSP_FILE)
		echo
		echo $RED"DANGEROUS COMMAND: Possible modification of runlevels FOUND on line: $LINE_12"$STAND
		echo "EXAMPLE:'telinit' followed by numbers 0-6' or similiar."
		echo "Can cause sudden system reboot/shutdown."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"'telinit' command not found."$STAND
	echo
	fi

	if
	$SU_PFX grep "$INIT" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_13=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$INIT" $SUSP_FILE)
		echo
		echo $RED"DANGEROUS COMMAND: Possible modification of runlevels FOUND on line: $LINE_13"$STAND
		echo "EXAMPLE:'init' followed by numbers 0-6' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo

	else
	echo $GRN"'init' command not found."$STAND
	echo
	fi

#Crontab changes
echo
echo $BLUE"Checking for crontab references"$STAND
CRONTAB_MOD="crontab >"

	if
	$SU_PFX grep "$CRONTAB_MOD" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_14=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$CRONTAB_MOD" $SUSP_FILE)
		echo $RED"DANGEROUS COMMAND: Possible crontab changes FOUND on line: $LINE_14"$STAND
		echo "EXAMPLE:'crontab > \$ANY_FILE' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"Crontab reference not found."$STAND
	echo
	fi

#/etc/shadow and /etc/passwd references
echo
echo $BLUE"Checking for '/etc/shadow' -or- '/etc/passwd' references"$STAND
ETC_SHADOW="/etc/shadow"
ETC_PASSWD="/etc/passwd"

	if
	$SU_PFX grep "$ETC_SHADOW" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_15=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$ETC_SHADOW" $SUSP_FILE)
		echo $RED"DANGEROUS: Scripts refers to '/etc/shadow' on line: $LINE_15"$STAND
		echo "EXAMPLE:'cat, cp or mv /etc/shadow' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"'/etc/shadow' reference not found."$STAND
	echo
	fi

	if
	$SU_PFX grep "$ETC_PASSWD" $SUSP_FILE > /dev/null 2>&1

		then
		LINE_16=$($SU_PFX awk '$0 ~ str{print NR-1 FS b}{b=$0}' str="$ETC_PASSWD" $SUSP_FILE )
		echo $RED"DANGEROUS: Scripts refers to '/etc/passwd' on line: $LINE_16"$STAND
		echo "EXAMPLE:'cat, cp or mv /etc/passwd' or similiar."
		RESULTS=$(( $RESULTS + 1 ))
		echo
	else
	echo $GRN"'/etc/passwd' reference not found."$STAND
	echo
	fi
	

scan_script_again

}

function checksum_compare() {
clear
echo
echo $GRN"---- CHECKSUM COMPARISON ----"$STAND
echo
echo "Press 'q' To Return"
echo
echo -ne "First Checksum: "
read FIRST_SUM

	case $FIRST_SUM in

		[qQ])
		main_menu
		;;

		*)
		echo
		;;

	esac

echo
echo -ne "Second Checksum: "
read SECOND_SUM

echo
diff <(echo "$FIRST_SUM") <(echo "$SECOND_SUM")
CHECKSUM_RESULT=$( echo $? )
echo
	if [ "$CHECKSUM_RESULT" == "0" ] ; then
		echo $GRN"CHECKSUMS MATCH"$STAND
	else
		echo $RED"CHECKSUMS DO NOT MATCH"$STAND
	fi

echo
echo "Press 'ENTER' To Continue"
read CHECKSUM_CHECK_CONT

	case $CHECKSUM_CHECK_CONT in

		*)
		main_menu
		;;

	esac
}

function scan_script_again() {

LINE_NUMBERS="Check line numbers above to review"

if [ $RESULTS -eq 0 ] ; then
	RESULTS_TALLY=$GREEN"NO SUSPICIOUS ITEMS FOUND"$STAND

elif [ $RESULTS -eq 1 ] ; then
	RESULTS_TALLY=$RED"1 SUSPICIOUS ITEM FOUND. Check the above line number to review."$STAND

elif [ $RESULTS -gt 1 ] ; then
	RESULTS_TALLY=$RED"$RESULTS SUSPICIOUS ITEMS FOUND."$STAND
fi

echo
echo $GRN"------ CHECKS COMPLETE ------"$STAND
echo
echo "$RESULTS_TALLY $LINE_NUMBERS"
echo
echo "NOTE: Script displays the preceding line to where an item was found."
echo "Eg: An object displayed as being on 'line 1' is actually on 'line 2'."
echo
echo "1) Scan Another File"
echo
echo "2) Return To Main Menu"
echo
echo -ne "Select Option: "
read SCAN_RET

	case $SCAN_RET in
		
		1)
		script_scan
		;;

		2)
		main_menu
		;;

		*)
		echo $RED"Invalid Option"$STAND
		sleep 1.5
		scan_script_again
		;;

	esac
}

function vpn_failsafe() {
clear
echo
echo $GRN"This feature will monitor the default interface set when your VPN is connected and if it fails"$STAND
echo $GRN"will lock down the firewall. By default firewall uses 'iptables'."$STAND
echo
echo $GRN"Options to use 'ufw' or to simply drop network interfaces exist. Uncomment to use."$STAND
echo
echo $YELL"Uncomment opening of port 22 or other if you may still need to connect remotely to host."$STAND
echo
echo $GRN"Default iptables rules will cause complete lockdown."$STAND
echo
echo "1) Start VPN failsafe"
echo
echo "2) Reopen Network"
echo
echo "Press 'q' To Return To Main Menu"
echo
echo -ne "Select Option: "
read VPN_CHECKER_START

	case $VPN_CHECKER_START in

		1)
		echo $GRN"VPN LEAK FAILSAFE IS RUNNING..."$STAND
		;;

		2)
		reopen_fw
		;;

		[qQ])
		main_menu
		;;

	esac

#Checks current iface
read INTERFACE <<< $( $SU_PFX ip route get $REMOTE_PING | awk 'NR==2 {print $1}' RS="dev" 2>/dev/null )
IFACE_FAIL=$( echo $? )

#Checks current iface is correct
while  [ "$INTERFACE" == "$VPN_IFACE" ]
	do
		sleep 0.1 #Throttles loop to reduce CPU load
		read INTERFACE <<< $( $SU_PFX ip route get $REMOTE_PING | awk 'NR==2 {print $1}' RS="dev" 2>/dev/null )
		IFACE_FAIL=$( echo $? )
	done

#If wrong iface
if [ "$INTERFACE" != "$VPN_IFACE" ] ; then

	#####Lock down using iptables####
	$SU_PFX iptables -F
	$SU_PFX iptables -P INPUT DROP
	$SU_PFX iptables -P OUTPUT DROP
	$SU_PFX iptables -P FORWARD DROP
	#Opening of port 22/ssh for remote connection
	#$SU_PFX iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
	#$SU_PFX iptables -A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT
	#$SU_PFX iptables -A FORWARD -p tcp -m tcp --dport 22 -j ACCEPT

	#####Total firewall lockdown with ufw####
	#ufw deny outgoing to 127.0.0.1
	#ufw deny incoming to 127.0.0.1
	#ufw allow from 127.0.0.1 to any port 22 proto tcp
	#ufw enable >/dev/null 2>&1

	#####Drop interface####
	#ifconfig $INTERFACE down

	#Return to main menu
	VPN_FAIL_TIME=$( $SU_PFX date )
	FUNCTION_FAIL=$RED"---- VPN FAILED on $VPN_FAIL_TIME (local time) AND SYSTEM WAS LOCKED DOWN ----"$STAND
	echo -en "\007"
	echo -en "\007"
	main_menu

#Exit if no interface available
elif [ $IFACE_FAIL != 0 ] ; then
	FUNCTION_FAIL=$RED"---- VPN Checker Exited. Error Code: $FACE_FAIL ----"$STAND
	main_menu
fi

}

function reopen_fw() {
clear
echo
echo
echo $GRN"Reopening network. Edit this section of script for your custom rulesets."$STAND
echo
echo "Default is open all. Consider adding 'exec' and path to your custom iptables scripted ruleset."
echo "Example: exec /root/Desktop/Myscripts/my_iptables_rules.sh"
echo
#####Lock down using iptables####
	$SU_PFX iptables -F
	$SU_PFX iptables -P INPUT ACCEPT
	$SU_PFX iptables -P OUTPUT ACCEPT
	$SU_PFX iptables -P FORWARD ACCEPT
	echo $GRN"Iptables Rules Reopened"$STAND

	#####Open UFW back up####
	#ufw accept outgoing to 127.0.0.1
	#ufw accept incoming to 127.0.0.1
	#ufw allow from 127.0.0.1 to any port 22 proto tcp
	#ufw disable >/dev/null 2>&1
	#echo $GRN"ufw Rules Reopened"$STAND

	#####ACCEPT interface####
	#ifconfig $INTERFACE up
	#echo $GRN"Interface re-enabled"$STAND

echo
echo "Press 'ENTER' to return to previous menu"
read OPENED_RETURN

	case $OPENED_RETURN in

		*)
		vpn_failsafe
		;;

	esac

}


function clean_up_0() {
clear
echo
echo "Script:$GRN$SCRIPT_NAME$STAND with PID:$GRN$PID$STAND cancelled by user: Likely 'Ctrl+C'.$GRN$USER_ID-$STAND SIGINT (2)"
echo
EX_CODE="USER INTERRUPT: SIGINT (2)"
clean_up_finish
}

function clean_up_1() {
clear
echo
echo "Script:$GRN$SCRIPT_NAME$STAND with PID:$GRN$PID$STAND caught signal to terminate from system- SIGTERM (15)."
EX_CODE="Terminated by SYSTEM: SIGTERM (15)"
echo
clean_up_finish
}

function clean_up_2() {
clear
echo
echo "Script:$GRN$SCRIPT_NAME$STAND with PID:$GRN$PID$STAND caught exit signal to hangup- SIGHUP (1)."
EX_CODE="HANGUP signal detected: SIGHUP (1)"
echo
clean_up_finish
}

function clean_up_finish() {
$SU_PFX shred -fuzn 3 /tmp/*$SCRIPT_NAME*
clear
echo
echo $YELL"Cleaning up temporary files and exiting..."$STAND
sleep 1
clear
echo "Script: $GRN'$SCRIPT_NAME'$STAND exited."
echo "UTC: $UTC"
echo "LOCAL: $LOCAL"
echo $RED"$EX_CODE"$STAND
exit 0
}

function config_check() {
clear
echo
echo $GRN"Checking script dependancies..."$STAND
echo
INSTALL_COUNT=0

#Check for openssh-server/sshd
if $SU_PFX which sshd > /dev/null ; then
	
	SSH_SERVER_CHECK=$GRN"OPENSSH-SERVER (sshd) INSTALLED"$STAND
	echo

		else
	echo
	SSH_SERVER_CHECK=$RED"OPENSSH-SERVER (sshd) NOT INSTALLED"$STAND
	INSTALL_COUNT=$(( $INSTALL_COUNT + 1 ))
	
fi

#Checking for secure-delete (srm)
if $SU_PFX which srm > /dev/null ; then

	echo
	SRM_CHECK=$GRN"SECURE-DELETE (srm) INSTALLED"$STAND

		else
	echo
	SRM_CHECK=$RED"SECURE-DELETE (srm) NOT INSTALLED"$STAND
	INSTALL_COUNT=$(( $INSTALL_COUNT + 1 ))
	
fi

#Checking for lm-sensors
if $SU_PFX which sensors > /dev/null ; then

	echo
	LM_SENS_CHECK=$GRN"LM-SENSORS INSTALLED"$STAND

		else
	echo
	LM_SENS_CHECK=$RED"LM-SENSORS NOT INSTALLED- REQUIRED FOR HEAT SENSORS."$STAND
	INSTALL_COUNT=$(( $INSTALL_COUNT + 1 ))
	
fi

#Check for geoiplookup
if $SU_PFX which geoiplookup > /dev/null ; then

	echo
	GEO_IP_CHECK=$GRN"GEOIPLOOKUP INSTALLED"$STAND

		else
	echo
	GEO_IP_CHECK=$RED"GEOIPLOOKUP"$STAND
	INSTALL_COUNT=$(( $INSTALL_COUNT + 1 ))
	
fi

#Counter checking number of items missing
if [ $INSTALL_COUNT -eq 1 ] ; then
	PACK_NUM=" 1 PACKAGE"

elif [ $INSTALL_COUNT -eq 2 ] ; then
	PACK_NUM="2 PACKAGES"

elif [ $INSTALL_COUNT -eq 3 ] ; then
	PACK_NUM="3 PACKAGES"

elif [ $INSTALL_COUNT -eq 4 ] ; then
	PACK_NUM="4 PACKAGES"

fi

if [ $INSTALL_COUNT -gt 0 ] ; then
		dependancies_missing

elif [ $INSTALL_COUNT -eq 0 ] ; then
		dependancies_ok
fi

}


function dependancies_missing() {
clear
echo
echo $RED"MISSING $PACK_NUM"$STAND
echo
echo "$SSH_SERVER_CHECK"
echo "$SRM_CHECK"
echo "$LM_SENS_CHECK"
echo "$GEO_IP_CHECK"
echo
echo "1) Run Installer."
echo
echo "Press 'q' to Return To Main Menu."
echo
echo -ne "Enter Selection: "
read MISS_RETURN

	case $MISS_RETURN in

		1)
		installer
		;;

		[qQ])
		main_menu
		;;

		*)
		echo
		echo $RED"Invalid Option."$STAND
		dependancies_missing
		;;

	esac
}

function dependancies_ok() {
clear
echo
echo $GRN"ALL Dependancies: OK"$STAND
echo
echo "openssh-server (sshd)"
echo
echo "lm-sensors (Required for CPU temperature check)."
echo
echo "secure-delete (srm)"
echo
echo "geoiplookup"
echo
echo
echo $YELL"Restart script for changes to take effect"$STAND
echo
echo "Press 'ENTER' to Return To Main Menu"
	read CONFIG_RETURN
			
		case $CONFIG_RETURN in
	
			*)
			if [ $START_COUNT -eq 0 ] ; then
			initialise_and_set_main

			elif [ $START_COUNT -gt 0 ] ; then
			main_menu
			fi
			;;

		esac

}
	
function installer() {
echo
#Install openssh-server/sshd
if
$SU_PFX which sshd > /dev/null ; then
	echo
else
	echo
	echo $YELL"Installing 'openssh-server' (sshd)"$STAND
	echo
	$SU_PFX $PKG openssh-server
fi

#Install srm
if
$SU_PFX which srm > /dev/null ; then
	echo
else
	echo
	echo $YELL"Installing 'secure-delete' (srm)"$STAND
	echo
	$SU_PFX $PKG secure-delete
fi

#Install sensors
if
$SU_PFX which sensors > /dev/null ; then
	echo
else
	echo
	echo $YELL"Installing 'lm-sensors'"$STAND
	$SU_PFX $PKG lm-sensors
fi

#Installing geoiplookup
if
$SU_PFX which geoiplookup > /dev/null ; then
	echo
else
	echo
	echo $YELL"Installing 'geoiplookup'"$STAND
	$SU_PFX $PKG geoip-bin
fi

config_check
}

function check_installer() {

CHECK_INSTALL=0

	#Checking for secure-delete
	if 
	$SU_PFX which srm > /dev/null ; then
		SRM_VACANT=""

		else

	SRM_VACANT=$YELL"Package, 'secure-delete' not installed. Component elements may not work."$STAND
	CHECK_INSTALL=$(( $CHECK_INSTALL + 1 ))
	fi

	#Check for lm-sensors
	if 
	$SU_PFX which sensors > /dev/null ; then
		LMS_VACANT=""

		else
	
	LMS_VACANT=$RED"Package, 'lm-sensors' not installed. CPU heat sensors will not work."$STAND
	CHECK_INSTALL=$(( $CHECK_INSTALL + 1 ))
	fi

	#Check for openssh-server/sshd
	if 
	$SU_PFX which sshd > /dev/null ; then
	SSH_SERV_VACANT=""

		else

	SSH_SERV_VACANT=$RED"Package, 'openssh-server' (sshd) not installed. Required."$STAND
	CHECK_INSTALL=$(( $CHECK_INSTALL + 1 ))
	fi

	#Check for geoip-lookup
	if $SU_PFX which geoiplookup > /dev/null ; then
	echo

		else

	GEO_IP_VACANT=$RED"Package, 'geoiplookup' not installed."$STAND
	CHECK_INSTALL=$(( $CHECK_INSTALL + 1 ))
	fi

	#Install count check		
	if [ $CHECK_INSTALL -eq 0 ] ; then

		CONF=$GRN"OK"$STAND
	else
		CONF=$RED"DEPENDANCIES MISSING. RUN CONFIG"$STAND
		
	fi

initialise_and_set_main

}

###############################

##Start of running script##

#Trap type and function to execute on event
trap clean_up_0 SIGINT
trap clean_up_1 SIGTERM
trap clean_up_2 SIGHUP

set_variables
