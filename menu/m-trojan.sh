#!/bin/bash

# Konfigurasi Warna
NC="\e[0m"
RED="\033[0;31m"
WH='\033[1;37m'
COLOR1="\033[0;32m"
COLBG1="\033[42m"

# Konfigurasi Path
CONFIG_FILE="/etc/xray/config.json"
TROJAN_DIR="/etc/trojan"
LOG_FILE="/var/log/xray/access.log"
TELEGRAM_URL="https://api.telegram.org/bot$KEY/sendMessage"

# Fungsi untuk memeriksa apakah file ada
check_file() {
    if [ ! -e "$1" ]; then
        echo "File $1 tidak ditemukan."
        return 1
    fi
    return 0
}

# Fungsi untuk menampilkan pesan error
error_message() {
    echo -e "$RED[ERROR]$NC $1"
}

# Fungsi untuk menampilkan pesan sukses
success_message() {
    echo -e "$COLOR1[SUCCESS]$NC $1"
}

# Fungsi untuk menambahkan akun Trojan
add-tr() {
    clear
    until [[ $user =~ ^[a-zA-Z0-9_.-]+$ && ${user_EXISTS} == '0' ]]; do
        echo -e "$COLOR1╭═════════════════════════════════════════════════╮${NC}"
        echo -e "$COLOR1│${NC}${COLBG1}            ${WH}• Add Trojan Account •               ${NC}$COLOR1│ $NC"
        echo -e "$COLOR1╰═════════════════════════════════════════════════╯${NC}"
        echo -e ""
        read -rp "User: " -e user
        user_EXISTS=$(grep -w $user $CONFIG_FILE | wc -l)
        if [[ ${user_EXISTS} == '1' ]]; then
            error_message "Nama Duplikat Silahkan Buat Nama Lain."
            add-tr
        fi
    done

    uuid=$(cat /proc/sys/kernel/random/uuid)
    until [[ $masaaktif =~ ^[0-9]+$ ]]; do
        read -p "Expired (hari): " masaaktif
    done
    exp=$(date -d "$masaaktif days" +"%Y-%m-%d")

    until [[ $iplim =~ ^[0-9]+$ ]]; do
        read -p "Limit User (IP) or 0 Unlimited: " iplim
    done

    until [[ $Quota =~ ^[0-9]+$ ]]; do
        read -p "Limit User (GB) or 0 Unlimited: " Quota
    done

    if [ ! -e $TROJAN_DIR ]; then
        mkdir -p $TROJAN_DIR
    fi

    if [ ${iplim} = '0' ]; then
        iplim="9999"
    fi

    if [ ${Quota} = '0' ]; then
        Quota="9999"
    fi

    c=$(echo "${Quota}" | sed 's/[^0-9]*//g')
    d=$((${c} * 1024 * 1024 * 1024))
    if [[ ${c} != "0" ]]; then
        echo "${d}" >$TROJAN_DIR/${user}
    fi

    echo "${iplim}" >$TROJAN_DIR/${user}IP

    sed -i '/#trojanws$/a\#tr '"$user $exp $uuid"'\
    },{"password": "'""$uuid""'","email": "'""$user""'"' $CONFIG_FILE
    sed -i '/#trojangrpc$/a\#trg '"$user $exp"'\
    },{"password": "'""$uuid""'","email": "'""$user""'"' $CONFIG_FILE

    trojanlink="trojan://${uuid}@${domain}:443?path=%2Ftrojan-ws&security=tls&host=${domain}&type=ws&sni=${domain}#${user}"
    trojanlink1="trojan://${uuid}@${domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${domain}#${user}"

    cat > /home/vps/public_html/trojan-$user.txt <<-END
    Format Trojan WS (CDN)
    -------------------------------
    - name: Trojan-$user-WS (CDN)
    server: ${domain}
    port: 443
    type: trojan
    password: ${uuid}
    network: ws
    sni: ${domain}
    skip-cert-verify: true
    udp: true
    ws-opts:
      path: /trojan-ws
      headers:
        Host: ${domain}
    -------------------------------
    Format Trojan gRPC
    -------------------------------
    - name: Trojan-$user-gRPC (SNI)
    type: trojan
    server: ${domain}
    port: 443
    password: ${uuid}
    udp: true
    sni: ${domain}
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: trojan-grpc
    -------------------------------
    Link Trojan Account
    -------------------------------
    Link WS : $trojanlink
    Link GRPC : $trojanlink1
    END

    success_message "Akun Trojan berhasil ditambahkan."
    read -n 1 -s -r -p "Press any key to back on menu"
    m-trojan
}

# Fungsi untuk trial akun Trojan
trial-trojan() {
    clear
    until [[ $timer =~ ^[0-9]+$ ]]; do
        read -p "Expired (Minutes): " timer
    done

    user="Trial-$(</dev/urandom tr -dc X-Z-0-9 | head -c4)"
    uuid=$(cat /proc/sys/kernel/random/uuid)
    masaaktif=1
    iplim=1
    Quota=10

    if [ ! -e $TROJAN_DIR ]; then
        mkdir -p $TROJAN_DIR
    fi

    c=$(echo "${Quota}" | sed 's/[^0-9]*//g')
    d=$((${c} * 1024 * 1024 * 1024))
    if [[ ${c} != "0" ]]; then
        echo "${d}" >$TROJAN_DIR/${user}
    fi

    echo "${iplim}" >$TROJAN_DIR/${user}IP

    sed -i '/#trojanws$/a\#tr '"$user $exp $uuid"'\
    },{"password": "'""$uuid""'","email": "'""$user""'"' $CONFIG_FILE
    sed -i '/#trojangrpc$/a\#trg '"$user $exp"'\
    },{"password": "'""$uuid""'","email": "'""$user""'"' $CONFIG_FILE

    trojanlink="trojan://${uuid}@${domain}:443?path=%2Ftrojan-ws&security=tls&host=${domain}&type=ws&sni=${domain}#${user}"
    trojanlink1="trojan://${uuid}@${domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${domain}#${user}"

    cat > /home/vps/public_html/trojan-$user.txt <<-END
    Format Trojan WS (CDN)
    -------------------------------
    - name: Trojan-$user-WS (CDN)
    server: ${domain}
    port: 443
    type: trojan
    password: ${uuid}
    network: ws
    sni: ${domain}
    skip-cert-verify: true
    udp: true
    ws-opts:
      path: /trojan-ws
      headers:
        Host: ${domain}
    -------------------------------
    Format Trojan gRPC
    -------------------------------
    - name: Trojan-$user-gRPC (SNI)
    type: trojan
    server: ${domain}
    port: 443
    password: ${uuid}
    udp: true
    sni: ${domain}
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: trojan-grpc
    -------------------------------
    Link Trojan Account
    -------------------------------
    Link WS : $trojanlink
    Link GRPC : $trojanlink1
    END

    success_message "Akun Trial Trojan berhasil ditambahkan."
    read -n 1 -s -r -p "Press any key to back on menu"
    m-trojan
}

# Fungsi untuk menampilkan menu utama
m-trojan() {
    clear
    echo -e " $COLOR1╭════════════════════════════════════════════════════╮${NC}"
    echo -e " $COLOR1│${NC} ${COLBG1}              ${WH}• TROJAN PANEL MENU •               ${NC} $COLOR1│ $NC"
    echo -e " $COLOR1╰════════════════════════════════════════════════════╯${NC}"
    echo -e " $COLOR1╭════════════════════════════════════════════════════╮${NC}"
    echo -e " $COLOR1│ $NC ${WH}[${COLOR1}01${WH}]${NC} ${COLOR1}• ${WH}ADD AKUN${NC}         ${WH}[${COLOR1}06${WH}]${NC} ${COLOR1}• ${WH}CEK USER CONFIG${NC}    $COLOR1│ $NC"
    echo -e " $COLOR1│ $NC ${WH}[${COLOR1}02${WH}]${NC} ${COLOR1}• ${WH}TRIAL AKUN${NC}       ${WH}[${COLOR1}07${WH}]${NC} ${COLOR1}• ${WH}CHANGE USER LIMIT${NC}  $COLOR1│ $NC"
    echo -e " $COLOR1│ $NC ${WH}[${COLOR1}03${WH}]${NC} ${COLOR1}• ${WH}RENEW AKUN${NC}       ${WH}[${COLOR1}08${WH}]${NC} ${COLOR1}• ${WH}SETTING LOCK LOGIN${NC} $COLOR1│ $NC"
    echo -e " $COLOR1│ $NC ${WH}[${COLOR1}04${WH}]${NC} ${COLOR1}• ${WH}DELETE AKUN${NC}      ${WH}[${COLOR1}09${WH}]${NC} ${COLOR1}• ${WH}UNLOCK USER LOGIN${NC}  $COLOR1│ $NC"
    echo -e " $COLOR1│ $NC ${WH}[${COLOR1}05${WH}]${NC} ${COLOR1}• ${WH}CEK USER LOGIN${NC}   ${WH}[${COLOR1}10${WH}]${NC} ${COLOR1}• ${WH}UNLOCK USER QUOTA ${NC} $COLOR1│ $NC"
    echo -e " $COLOR1│ $NC ${WH}[${COLOR1}00${WH}]${NC} ${COLOR1}• ${WH}GO BACK${NC}          ${WH}[${COLOR1}11${WH}]${NC} ${COLOR1}• ${WH}RESTORE AKUN   ${NC}    $COLOR1│ $NC"
    echo -e " $COLOR1╰════════════════════════════════════════════════════╯${NC}"
    echo -e " $COLOR1╭═════════════════════════ ${WH}BY${NC} ${COLOR1}═══════════════════════╮ ${NC}"
    printf "                      ${COLOR1}%3s${NC} ${WH}%0s${NC} ${COLOR1}%3s${NC}\n" "• " "$author" " •"
    echo -e " $COLOR1╰════════════════════════════════════════════════════╯${NC}"
    echo -e ""
    echo -ne " ${WH}Select menu ${COLOR1}: ${WH}"; read opt
    case $opt in
        01 | 1) clear ; add-tr ;;
        02 | 2) clear ; trial-trojan ;;
        03 | 3) clear ; renew-tr ;;
        04 | 4) clear ; del-tr ;;
        05 | 5) clear ; cek-tr ;;
        06 | 6) clear ; list-trojan ;;
        07 | 7) clear ; limit-tr ;;
        08 | 8) clear ; login-tr ;;
        09 | 9) clear ; lock-tr ;;
        10 | 10) clear ; quota-user ;;
        11 | 11) clear ; res-user ;;
        00 | 0) clear ; menu ;;
        x) exit ;;
        *) echo "SALAH TEKAN" ; sleep 1 ; m-trojan ;;
    esac
}

# Panggil fungsi utama
m-trojan
