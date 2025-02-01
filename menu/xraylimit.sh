#!/bin/bash
# Config
NC="\e[0m"
RED="\033[0;31m"
WH='\033[1;37m'
TIMES="10"
CHATID=$(cat /etc/perlogin/id)
KEY=$(cat /etc/perlogin/token)
URL="https://api.telegram.org/bot$KEY/sendMessage"
DOMAIN=$(cat /etc/xray/domain)
ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)
DATE=$(date +'%Y-%m-%d')
TIME=$(date +'%H:%M:%S')
AUTHOR=$(cat /etc/profil)
TYPE=$(cat /etc/typexray)
WAKTULOCK=$(cat /etc/waktulock)

# Function to convert bytes to human-readable format
function convert() {
  local -i bytes=$1
  if [[ $bytes -lt 1024 ]]; then
    echo "${bytes} B"
  elif [[ $bytes -lt 1048576 ]]; then
    echo "$(((bytes + 1023) / 1024)) KB"
  elif [[ $bytes -lt 1073741824 ]]; then
    echo "$(((bytes + 1048575) / 1048576)) MB"
  else
    echo "$(((bytes + 1073741823) / 1073741824)) GB"
  fi
}

# Function to handle VMess users
function vmess() {
  if [[ ! -e /etc/limit/vmess ]]; then
    mkdir -p /etc/limit/vmess
  fi

  VMESS_USERS=($(grep "^#vmg" /etc/xray/config.json | awk '{print $2}' | sort -u))
  for USER in "${VMESS_USERS[@]}"; do
    LOG=$(grep -w "email: ${USER}" /var/log/xray/access.log | tail -n 150)
    IP_COUNT=$(echo "$LOG" | awk '{print $7}' | sort -u | wc -l)

    # Get traffic stats
    TRAFFIC=$(xray api stats --server=127.0.0.1:10085 -name "user>>>${USER}>>>traffic>>>downlink" 2>/dev/null | grep -w "value" | awk '{print $2}' | cut -d '"' -f2)
    if [[ -z "$TRAFFIC" ]]; then
      TRAFFIC=0
    fi

    # Update usage
    if [[ ! -e /etc/limit/vmess/${USER} ]]; then
      echo "$TRAFFIC" > /etc/limit/vmess/${USER}
    else
      PREV_TRAFFIC=$(cat /etc/limit/vmess/${USER})
      TOTAL_TRAFFIC=$((TRAFFIC + PREV_TRAFFIC))
      echo "$TOTAL_TRAFFIC" > /etc/limit/vmess/${USER}
    fi

    # Check quota limit
    LIMIT=$(cat /etc/vmess/${USER} 2>/dev/null || echo "999999999999")
    if [[ $TOTAL_TRAFFIC -gt $LIMIT ]]; then
      EXP=$(grep -wE "^#vmg ${USER}" /etc/xray/config.json | awk '{print $3}')
      UUID=$(grep -wE "^#vmg ${USER}" /etc/xray/config.json | awk '{print $4}')
      echo "### ${USER} ${EXP} ${UUID}" >> /etc/vmess/userQuota
      sed -i "/^#vmg ${USER} ${EXP}/,/^},{/d" /etc/xray/config.json
      sed -i "/^#vm ${USER} ${EXP}/,/^},{/d" /etc/xray/config.json
      rm -f /etc/limit/vmess/${USER}
      systemctl restart xray
    fi

    # Check multi-login
    IP_LIMIT=$(cat /etc/vmess/${USER}IP 2>/dev/null || echo "0")
    if [[ $IP_COUNT -gt $IP_LIMIT ]]; then
      BYTES=$(cat /etc/limit/vmess/${USER})
      GB=$(convert $BYTES)
      echo "${USER} ${IP_COUNT}" >> /etc/vmess/${USER}login
      NOTIF_COUNT=$(cat /etc/vmess/notif 2>/dev/null || echo "3")

      if [[ $IP_COUNT -ge $NOTIF_COUNT ]]; then
        if [[ "$TYPE" == "lock" ]]; then
          TEXT="<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ VMESS MULTI LOGIN</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>USERNAME : ${USER}</b>
<b>IP LOGIN : ${IP_COUNT}</b>
<b>USAGE : ${GB}</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>Account locked for ${WAKTULOCK} minutes.</i>"
          curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
          echo "### ${USER} ${EXP} ${UUID}" >> /etc/vmess/listlock
          sed -i "/^#vmg ${USER} ${EXP}/,/^},{/d" /etc/xray/config.json
          sed -i "/^#vm ${USER} ${EXP}/,/^},{/d" /etc/xray/config.json
          rm -f /etc/vmess/${USER}login
          systemctl restart xray
        elif [[ "$TYPE" == "delete" ]]; then
          TEXT="<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ VMESS MULTI LOGIN</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>USERNAME : ${USER}</b>
<b>IP LOGIN : ${IP_COUNT}</b>
<b>USAGE : ${GB}</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>Account deleted due to multi-login.</i>"
          curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
          echo "### ${USER} ${EXP} ${UUID}" >> /etc/vmess/listlock
          sed -i "/^#vmg ${USER} ${EXP}/,/^},{/d" /etc/xray/config.json
          sed -i "/^#vm ${USER} ${EXP}/,/^},{/d" /etc/xray/config.json
          rm -f /etc/vmess/${USER}login
          systemctl restart xray
        fi
      fi
    fi
  done
}
# Call functions
vmess
function vless() {
cd
if [[ ! -e /etc/limit/vless ]]; then
mkdir -p /etc/limit/vless
fi
vldat=($(cat /etc/xray/config.json | grep "^#vlg" | awk '{print $2}' | sort -u))
echo -n >/tmp/vl
for db2 in ${vldat[@]}; do
logvl=$(cat /var/log/xray/access.log | grep -w "email: ${db2}" | tail -n 150)
while read a; do
if [[ -n ${a} ]]; then
set -- ${a}
ina="${7}"
inu="${2}"
anu="${3}"
enu=$(echo "${anu}" | sed 's/tcp://g' | sed '/^$/d' | cut -d. -f1,2,3)
now=$(tim2sec ${timenow})
client=$(tim2sec ${inu})
nowt=$(((${now} - ${client})))
if [[ ${nowt} -lt 40 ]]; then
cat /tmp/vl | grep -w "${ina}" | grep -w "${enu}" >/dev/null
if [[ $? -eq 1 ]]; then
echo "${ina} ${inu} WIB : ${enu}" >>/tmp/vl
spll=$(cat /tmp/vl)
fi
fi
fi
done <<<"${logvl}"
done
if [[ ${spll} != "" ]]; then
for vlus in ${vldat[@]}; do
vlsss=$(cat /tmp/vl | grep -w "${vlus}" | wc -l)
vlsss2=$(cat /tmp/vl | grep -w "${vlus}" | cut -d ' ' -f 2-8 | nl -s '. ' | while read line; do printf "%-20s\n" "$line"; done )
sdf=$(ls "/etc/vless" | grep -w "${vlus}IP")
if [[ -z ${sdf} ]]; then
vmip="0"
else
vmip=$(cat /etc/vless/${vlus}IP)
fi
if [[ ${vlsss} -gt "0" ]]; then
downlink=$(xray api stats --server=127.0.0.1:10085 -name "user>>>${vlus}>>>traffic>>>downlink" | grep -w "value" | awk '{print $2}' | cut -d '"' -f2)
cd
if [ ! -e /etc/limit/vless/${vlus} ]; then
echo "${downlink}" > /etc/limit/vless/${vlus}
xray api stats --server=127.0.0.1:10085 -name "user>>>${vlus}>>>traffic>>>downlink" -reset > /dev/null 2>&1
else
plus2=$(cat /etc/limit/vless/${vlus})
cd
if [[ -z ${plus2} ]]; then
echo "1" > /etc/limit/vless/${vlus}
fi
plus3=$(( ${downlink} + ${plus2} ))
echo "${plus3}" > /etc/limit/vless/${vlus}
xray api stats --server=127.0.0.1:10085 -name "user>>>${vlus}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
cd
if [ ! -e /etc/vless/${vlus} ]; then
echo "999999999999" > /etc/vless/${vlus}
fi
limit=$(cat /etc/vless/${vlus})
usage=$(cat /etc/limit/vless/${vlus})
if [ $usage -gt $limit ]; then
expvl=$(grep -wE "^#vl $vlus" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
uuidvl=$(grep -wE "^#vl $vlus" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
echo "### $vlus $expvl $uuidvl" >> /etc/vless/userQuota
sed -i "/^#vl $vlus $expvl/,/^},{/d" /etc/xray/config.json
sed -i "/^#vlg $vlus $expvl/,/^},{/d" /etc/xray/config.json
rm /etc/limit/vless/${vlus} >/dev/null 2>&1
systemctl restart xray >/dev/null 2>&1
fi
fi
if [[ ${vlsss} -gt $vmip ]]; then
byt=$(cat /etc/limit/vless/$vlus)
gb=$(convert ${byt})
echo "$vlus ${vlsss}" >> /etc/vless/${vlus}login
vlessip=$(cat /etc/vless/${vlus}login | wc -l)
ssvless1=$(ls "/etc/vless" | grep -w "notif")
if [[ -z ${ssvless1} ]]; then
ssvless="3"
else
ssvless=$(cat /etc/vless/notif)
fi
if [ $vlessip = $ssvless ]; then
echo -ne
if [ $type = "delete" ]; then
TEXT2="
<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ VLESS MULTI LOGIN</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${domen} </b>
<b>ISP : ${ISP}</b>
<b>CITY : ${CITY}</b>
<b>DATE LOGIN : $DATE</b>
<b>USERNAME : $vlus </b>
<b>TOTAL LOGIN IP : ${vlsss} </b>
<b>USAGE : ${gb} </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>⚠️ TIME LOGIN : IP LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>$vlsss2</code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>${ssvless}x Multi Login Auto Lock Account...</i>
"
echo "" > /tmp/vl
sed -i "/${vlus}/d" /var/log/xray/access.log
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT2&parse_mode=html" $URL >/dev/null
expvl=$(grep -wE "^#vl $vlus" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
uuidvl=$(grep -wE "^#vl $vlus" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
echo "### $vlus $expvl $uuidvl" >> /etc/vless/listlock
sed -i "/^#vl $vlus $expvl/,/^},{/d" /etc/xray/config.json
sed -i "/^#vlg $vlus $expvl/,/^},{/d" /etc/xray/config.json
rm /etc/vless/${vlus}login >/dev/null 2>&1
systemctl restart xray >/dev/null 2>&1
fi
if [ $type = "lock" ]; then
TEXT2="
<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ VLESS MULTI LOGIN</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${domen} </b>
<b>ISP : ${ISP}</b>
<b>CITY : ${CITY}</b>
<b>DATE LOGIN : $DATE</b>
<b>USERNAME : $vlus </b>
<b>TOTAL LOGIN IP : ${vlsss} </b>
<b>USAGE : ${gb} </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>⚠️ TIME LOGIN : IP LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>$vlsss2</code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>${ssvless}x Multi Login Lock Account $waktulock Minutes...</i>
"
echo "" > /tmp/vl
sed -i "/${vlus}/d" /var/log/xray/access.log
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT2&parse_mode=html" $URL >/dev/null
expvl=$(grep -wE "^#vl $vlus" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
uuidvl=$(grep -wE "^#vl $vlus" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
echo "### $vlus $expvl $uuidvl" >> /etc/vless/listlock
sed -i "/^#vl $vlus $expvl/,/^},{/d" /etc/xray/config.json
sed -i "/^#vlg $vlus $expvl/,/^},{/d" /etc/xray/config.json
rm /etc/vless/${vlus}login >/dev/null 2>&1
cat> /etc/cron.d/vless${vlus} << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/$waktulock * * * * root /usr/bin/xray vless $vlus $uuidvl $expvl
EOF
systemctl restart xray
service cron restart
fi
else
TEXT="
<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ VLESS MULTI LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${domen} </b>
<b>ISP : ${ISP}</b>
<b>CITY : ${CITY}</b>
<b>DATE LOGIN : $DATE</b>
<b>USERNAME : $vlus </b>
<b>TOTAL LOGIN IP : ${vlsss} </b>
<b>USAGE : ${gb} </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>⚠️ TIME LOGIN : IP LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>$vlsss2</code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>${vlessip}x Multi Login : ${ssvless}x Multi Login Auto Lock Account..</i>
"
echo "" > /tmp/vl
sed -i "/${vlus}/d" /var/log/xray/access.log
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
fi
if [ $vlessip -gt $ssvless ]; then
expvl=$(grep -wE "^#vl $vlus" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
uuidvl=$(grep -wE "^#vl $vlus" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
echo "### $vlus $expvl $uuidvl" >> /etc/vless/listlock
sed -i "/^#vl $vlus $expvl/,/^},{/d" /etc/xray/config.json
sed -i "/^#vlg $vlus $expvl/,/^},{/d" /etc/xray/config.json
rm /etc/vless/${vlus}login >/dev/null 2>&1
systemctl restart xray >/dev/null 2>&1
fi
fi
done
fi
}
# Fungsi untuk mengonversi waktu ke detik
function tim2sec() {
  local time=$1
  IFS=':' read -r h m s <<< "$time"
  echo $((h * 3600 + m * 60 + s))
}

# Fungsi utama Trojan
function trojan() {
  cd
  if [[ ! -e /etc/limit/trojan ]]; then
    mkdir -p /etc/limit/trojan
  fi

  trda=($(cat /etc/xray/config.json | grep "^#trg" | awk '{print $2}' | sort -u))
  echo -n > /tmp/tr

  for db3 in "${trda[@]}"; do
    logtr=$(cat /var/log/xray/access.log | grep -w "email: ${db3}" | tail -n 150)
    while read -r a; do
      if [[ -n ${a} ]]; then
        set -- ${a}
        ina="${7}"
        inu="${2}"
        anu="${3}"
        enu=$(echo "${anu}" | sed 's/tcp://g' | sed '/^$/d' | cut -d. -f1,2,3)

        # Konversi waktu ke detik menggunakan fungsi tim2sec
        now=$(date +%s)
        client=$(tim2sec "${inu}" 2>/dev/null || echo 0)
        nowt=$((now - client))

        if [[ ${nowt} -lt 40 ]]; then
          if ! grep -qw "${ina}" /tmp/tr; then
            echo "${ina} ${inu} WIB : ${enu}" >> /tmp/tr
          fi
        fi
      fi
    done <<< "${logtr}"
  done

  if [[ -s /tmp/tr ]]; then
    for usrtr in "${trda[@]}"; do
      trip=$(grep -w "${usrtr}" /tmp/tr | wc -l)
      trip2=$(grep -w "${usrtr}" /tmp/tr | cut -d ' ' -f 2-8 | nl -s '. ' | while read line; do printf "%-20s\n" "$line"; done)

      sdf=$(ls "/etc/trojan" | grep -w "${usrtr}IP")
      if [[ -z ${sdf} ]]; then
        sadsde="0"
      else
        sadsde=$(cat /etc/trojan/${usrtr}IP)
      fi

      if [[ ${trip} -gt "0" ]]; then
        downlink=$(xray api stats --server=127.0.0.1:10085 -name "user>>>${usrtr}>>>traffic>>>downlink" | grep -w "value" | awk '{print $2}' | cut -d '"' -f2)
        cd
        if [[ ! -e /etc/limit/trojan/${usrtr} ]]; then
          echo "${downlink}" > /etc/limit/trojan/${usrtr}
          xray api stats --server=127.0.0.1:10085 -name "user>>>${usrtr}>>>traffic>>>downlink" -reset > /dev/null 2>&1
        else
          plus2=$(cat /etc/limit/trojan/${usrtr})
          if [[ -z ${plus2} ]]; then
            echo "1" > /etc/limit/trojan/${usrtr}
          fi
          plus3=$((downlink + plus2))
          echo "${plus3}" > /etc/limit/trojan/${usrtr}
          xray api stats --server=127.0.0.1:10085 -name "user>>>${usrtr}>>>traffic>>>downlink" -reset > /dev/null 2>&1
        fi

        if [[ ! -e /etc/trojan/${usrtr} ]]; then
          echo "999999999999" > /etc/trojan/${usrtr}
        fi

        limit=$(cat /etc/trojan/${usrtr})
        usage=$(cat /etc/limit/trojan/${usrtr})
        if [[ ${usage} -gt ${limit} ]]; then
          exptr=$(grep -wE "^#tr ${usrtr}" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
          uuidtr=$(grep -wE "^#tr ${usrtr}" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
          echo "### ${usrtr} ${exptr} ${uuidtr}" >> /etc/trojan/userQuota
          sed -i "/^#tr ${usrtr} ${exptr}/,/^},{/d" /etc/xray/config.json
          sed -i "/^#trg ${usrtr} ${exptr}/,/^},{/d" /etc/xray/config.json
          rm -f /etc/limit/trojan/${usrtr} > /dev/null 2>&1
          systemctl restart xray > /dev/null 2>&1
        fi
      fi

      if [[ ${trip} -gt ${sadsde} ]]; then
        byt=$(cat /etc/limit/trojan/${usrtr} 2>/dev/null || echo 0)
        gb=$(convert ${byt})
        echo "${usrtr} ${trip}" >> /etc/trojan/${usrtr}login
        trojanip=$(cat /etc/trojan/${usrtr}login | wc -l)
        sstrojan1=$(ls "/etc/trojan" | grep -w "notif")
        if [[ -z ${sstrojan1} ]]; then
          sstrojan="3"
        else
          sstrojan=$(cat /etc/trojan/notif)
        fi

        if [[ ${trojanip} -eq ${sstrojan} ]]; then
          if [[ ${TYPE} == "delete" ]]; then
            TEXT2="
<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ TROJAN MULTI LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${DOMAIN} </b>
<b>ISP : ${ISP}</b>
<b>CITY : ${CITY}</b>
<b>DATE LOGIN : ${DATE}</b>
<b>USERNAME : ${usrtr} </b>
<b>TOTAL LOGIN IP : ${trip} </b>
<b>USAGE : ${gb} </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>⚠️ TIME LOGIN : IP LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>${trip2}</code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>${sstrojan}x Multi Login Auto Lock Account...</i>"
            echo "" > /tmp/tr
            sed -i "/${usrtr}/d" /var/log/xray/access.log
            curl -s --max-time ${TIMES} -d "chat_id=${CHATID}&disable_web_page_preview=1&text=${TEXT2}&parse_mode=html" ${URL} > /dev/null
            exptr=$(grep -wE "^#tr ${usrtr}" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
            uuidtr=$(grep -wE "^#tr ${usrtr}" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
            echo "### ${usrtr} ${exptr} ${uuidtr}" >> /etc/trojan/listlock
            sed -i "/^#tr ${usrtr} ${exptr}/,/^},{/d" /etc/xray/config.json
            sed -i "/^#trg ${usrtr} ${exptr}/,/^},{/d" /etc/xray/config.json
            rm -f /etc/trojan/${usrtr}login > /dev/null 2>&1
            systemctl restart xray > /dev/null 2>&1
          elif [[ ${TYPE} == "lock" ]]; then
            TEXT2="
<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ TROJAN MULTI LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${DOMAIN} </b>
<b>ISP : ${ISP}</b>
<b>CITY : ${CITY}</b>
<b>DATE LOGIN : ${DATE}</b>
<b>USERNAME : ${usrtr} </b>
<b>TOTAL LOGIN IP : ${trip} </b>
<b>USAGE : ${gb} </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>⚠️ TIME LOGIN : IP LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>${trip2}</code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>${sstrojan}x Multi Login Lock Account ${WAKTULOCK} Minutes...</i>"
            echo "" > /tmp/tr
            sed -i "/${usrtr}/d" /var/log/xray/access.log
            curl -s --max-time ${TIMES} -d "chat_id=${CHATID}&disable_web_page_preview=1&text=${TEXT2}&parse_mode=html" ${URL} > /dev/null
            exptr=$(grep -wE "^#tr ${usrtr}" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
            uuidtr=$(grep -wE "^#tr ${usrtr}" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
            echo "### ${usrtr} ${exptr} ${uuidtr}" >> /etc/trojan/listlock
            sed -i "/^#tr ${usrtr} ${exptr}/,/^},{/d" /etc/xray/config.json
            sed -i "/^#trg ${usrtr} ${exptr}/,/^},{/d" /etc/xray/config.json
            rm -f /etc/trojan/${usrtr}login > /dev/null 2>&1
            cat > /etc/cron.d/trojan${usrtr} << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/${WAKTULOCK} * * * * root /usr/bin/xray trojan ${usrtr} ${uuidtr} ${exptr}
EOF
            systemctl restart xray
            service cron restart
          fi
        fi
      fi
    done
  fi
}
####### TROJAN-GO #######
function trojan-go() {
cd
if [[ ! -e /etc/limit/trojan-go ]]; then
mkdir -p /etc/limit/trojan-go
fi
trda=($(cat /etc/xray/config.json | grep "^#trg" | awk '{print $2}' | sort -u))
echo -n >/tmp/tr
for db3 in ${trda[@]}; do
logtr=$(cat /var/log/xray/access.log | grep -w "email: ${db3}" | tail -n 150)
while read a; do
if [[ -n ${a} ]]; then
set -- ${a}
ina="${7}"
inu="${2}"
anu="${3}"
enu=$(echo "${anu}" | sed 's/tcp://g' | sed '/^$/d' | cut -d. -f1,2,3)
now=$(tim2sec ${timenow})
client=$(tim2sec ${inu})
nowt=$(((${now} - ${client})))
if [[ ${nowt} -lt 40 ]]; then
cat /tmp/tr | grep -w "${ina}" | grep -w "${enu}" >/dev/null
if [[ $? -eq 1 ]]; then
echo "${ina} ${inu} WIB : ${enu}" >>/tmp/tr
restr=$(cat /tmp/tr)
fi
fi
fi
done <<<"${logtr}"
done
if [[ ${restr} != "" ]]; then
for usrtr in ${trda[@]}; do
trip=$(cat /tmp/tr | grep -w "${usrtr}" | wc -l)
trip2=$(cat /tmp/tr | grep -w "${usrtr}" | cut -d ' ' -f 2-8 | nl -s '. ' | while read line; do printf "%-20s\n" "$line"; done )
sdf=$(ls "/etc/trojan-go" | grep -w "${usrtr}IP")
if [[ -z ${sdf} ]]; then
sadsde="0"
else
sadsde=$(cat /etc/trojan-go/${usrtr}IP)
fi
if [[ ${trip} -gt "0" ]]; then
downlink=$(xray api stats --server=127.0.0.1:10085 -name "user>>>${usrtr}>>>traffic>>>downlink" | grep -w "value" | awk '{print $2}' | cut -d '"' -f2)
cd
if [ ! -e /etc/limit/trojan-go/$usrtr ]; then
echo "${downlink}" > /etc/limit/trojan-go/${usrtr}
xray api stats --server=127.0.0.1:10085 -name "user>>>${usrtr}>>>traffic>>>downlink" -reset > /dev/null 2>&1
else
plus2=$(cat /etc/limit/trojan-go/$usrtr)
if [[ -z ${plus2} ]]; then
echo "1" > /etc/limit/trojan-go/$usrtr
fi
plus3=$(( ${downlink} + ${plus2} ))
echo "${plus3}" > /etc/limit/trojan-go/${usrtr}
xray api stats --server=127.0.0.1:10085 -name "user>>>${usrtr}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
if [ ! -e /etc/trojan-go/${usrtr} ]; then
echo "999999999999" > /etc/trojan-go/${usrtr}
fi
limit=$(cat /etc/trojan-go/${usrtr})
usage=$(cat /etc/limit/trojan-go/${usrtr})
if [ $usage -gt $limit ]; then
exptr=$(grep -wE "^#tr $usrtr" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
uuidtr=$(grep -wE "^#tr $usrtr" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
echo "### $usrtr $exptr $uuidtr" >> /etc/trojan-go/userQuota
sed -i "/^#tr $usrtr $exptr/,/^},{/d" /etc/xray/config.json
sed -i "/^#trg $usrtr $exptr/,/^},{/d" /etc/xray/config.json
rm /etc/limit/trojan-go/${usrtr} >/dev/null 2>&1
systemctl restart xray >/dev/null 2>&1
fi
fi
if [[ ${trip} -gt $sadsde ]]; then
byt=$(cat /etc/limit/trojan-go/$usrtr)
gb=$(convert ${byt})
echo "$usrtr ${trip}" >> /etc/trojan-go/${usrtr}login
trojanip=$(cat /etc/trojan-go/${usrtr}login | wc -l)
sstrojan1=$(ls "/etc/trojan-go" | grep -w "notif")
if [[ -z ${sstrojan1} ]]; then
sstrojan="3"
else
sstrojan=$(cat /etc/trojan-go/notif)
fi
if [ $trojanip = $sstrojan ]; then
echo -ne
if [ $type = "delete" ]; then
TEXT2="
<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ TROJAN MULTI LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${domen} </b>
<b>ISP : ${ISP}</b>
<b>CITY : ${CITY}</b>
<b>DATE LOGIN : $DATE</b>
<b>USERNAME : $usrtr </b>
<b>TOTAL LOGIN IP : ${trip} </b>
<b>USAGE : ${gb} </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>⚠️ TIME LOGIN : IP LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>$trip2</code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>${sstrojan}x Multi Login Auto Lock Account...</i>
"
echo "" > /tmp/tr
sed -i "/${usrtr}/d" /var/log/xray/access.log
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT2&parse_mode=html" $URL >/dev/null
exptr=$(grep -wE "^#tr $usrtr" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
uuidtr=$(grep -wE "^#tr $usrtr" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
echo "### $usrtr $exptr $uuidtr" >> /etc/trojan-go/listlock
sed -i "/^#tr $usrtr $exptr/,/^},{/d" /etc/xray/config.json
sed -i "/^#trg $usrtr $exptr/,/^},{/d" /etc/xray/config.json
rm /etc/trojan-go/${usrtr}login >/dev/null 2>&1
systemctl restart xray >/dev/null 2>&1
fi
if [ $type = "lock" ]; then
TEXT2="
<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ TROJAN MULTI LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${domen} </b>
<b>ISP : ${ISP}</b>
<b>CITY : ${CITY}</b>
<b>DATE LOGIN : $DATE</b>
<b>USERNAME : $usrtr </b>
<b>TOTAL LOGIN IP : ${trip} </b>
<b>USAGE : ${gb} </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>⚠️ TIME LOGIN : IP LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>$trip2</code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>${sstrojan}x Multi Login Lock Account $waktulock Minutes...</i>
"
echo "" > /tmp/tr
sed -i "/${usrtr}/d" /var/log/xray/access.log
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT2&parse_mode=html" $URL >/dev/null
exptr=$(grep -wE "^#tr $usrtr" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
uuidtr=$(grep -wE "^#tr $usrtr" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
echo "### $usrtr $exptr $uuidtr" >> /etc/trojan-go/listlock
sed -i "/^#tr $usrtr $exptr/,/^},{/d" /etc/xray/config.json
sed -i "/^#trg $usrtr $exptr/,/^},{/d" /etc/xray/config.json
rm /etc/trojan-go/${usrtr}login >/dev/null 2>&1
cat> /etc/cron.d/trojan-go${usrtr} << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/$waktulock * * * * root /usr/bin/xray trojan-go $usrtr $uuidtr $exptr
EOF
systemctl restart xray
service cron restart
fi
else
TEXT="
<code>◇━━━━━━━━━━━━━━◇</code>
<b> ⚠️ TROJAN MULTI LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${domen} </b>
<b>ISP : ${ISP}</b>
<b>CITY : ${CITY}</b>
<b>DATE LOGIN : $DATE</b>
<b>USERNAME : $usrtr </b>
<b>TOTAL LOGIN IP : ${trip} </b>
<b>USAGE : ${gb} </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>⚠️ TIME LOGIN : IP LOGIN </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>$trip2</code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>${trojanip}x Multi Login : ${sstrojan}x Multi Login Auto Lock Account...</i>
"
echo "" > /tmp/tr
sed -i "/${usrtr}/d" /var/log/xray/access.log
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
fi
if [ $trojanip -gt $sstrojan ]; then
exptr=$(grep -wE "^#tr $usrtr" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
uuidtr=$(grep -wE "^#tr $usrtr" "/etc/xray/config.json" | cut -d ' ' -f 4 | sort | uniq)
echo "### $usrtr $exptr $uuidtr" >> /etc/trojan-go/listlock
sed -i "/^#tr $usrtr $exptr/,/^},{/d" /etc/xray/config.json
sed -i "/^#trg $usrtr $exptr/,/^},{/d" /etc/xray/config.json
rm /etc/trojan-go/${usrtr}login >/dev/null 2>&1
systemctl restart xray >/dev/null 2>&1
fi
fi
done
fi
}
vmess
vless
trojan
trojan-go
