#!/bin/bash

# ===============================================
# 1. CONFIGURACIÓN Y VARIABLES
# ===============================================
# Configuración de colores (simplificada)
NC="\e[0m"
RED="\033[0;31m"
WH='\033[1;37m'
# Se asume que /etc/rmbl/theme/color.conf existe y funciona.
colornow=$(cat /etc/rmbl/theme/color.conf)
COLOR1="$(cat /etc/rmbl/theme/$colornow | grep -w "TEXT" | cut -d: -f2|sed 's/ //g')"
COLBG1="$(cat /etc/rmbl/theme/$colornow | grep -w "BG" | cut -d: -f2|sed 's/ //g')"

# Variables de tiempo, IP y datos de Telegram
data_server=$(curl -v --insecure --silent http://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")
ipsaya=$(curl -sS ifconfig.me)
data_ip="https://raw.githubusercontent.com/josecarlosmeza/permission/main/ip"
TIMES="10"
CHATID=$(cat /etc/perlogin/id 2>/dev/null) # Manejo de error si el archivo no existe
KEY=$(cat /etc/perlogin/token 2>/dev/null)
URL="https://api.telegram.org/bot$KEY/sendMessage"

# Variables de Servidor
domen=$(cat /etc/xray/domain)
DATE=$(date +'%Y-%m-%d')
ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)

# Lógica de bloqueo
type=$(cat /etc/typessh 2>/dev/null)
waktulock=$(cat /etc/waktulockssh 2>/dev/null)
limitip="" # Inicializado, se llenará más tarde por usuario

if [[ -z ${waktulock} ]]; then
echo "15" > /etc/waktulockssh
waktulock=15
fi
if [[ -z ${type} ]]; then
echo "delete" > /etc/typessh
type="delete"
fi

# ===============================================
# 2. FUNCIONES
# ===============================================

checking_sc() {
    # Función para la verificación de licencia/permisos
    useexp=$(curl --silent $data_ip | grep $ipsaya | awk '{print $3}')
    if [[ $date_list < $useexp ]]; then
        echo -ne
    else
        echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
        echo -e "$COLOR1 ${NC} ${COLBG1}          ${WH}• AUTOSCRIPT PREMIUM •               ${NC} $COLOR1 $NC"
        echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
        echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
        echo -e "            ${RED}PERMISSION DENIED !${NC}"
        echo -e "   \033[0;33mYour VPS${NC} $ipsaya \033[0;33mHas been Banned${NC}"
        echo -e "     \033[0;33mBuy access permissions for scripts${NC}"
        echo -e "             \033[0;33mContact Admin :${NC}"
        echo -e "     \033[0;36mTelegram${NC}: https://t.me/Rmblvpn1"
        echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
        exit 1
    fi
}

get_log_source() {
    # Determina el archivo de log y el tipo de OS
    if [ -e "/var/log/auth.log" ]; then
        OS=1
        LOG="/var/log/auth.log"
    elif [ -e "/var/log/secure" ]; then
        OS=2
        LOG="/var/log/secure"
    else
        echo "Error: No se encontró el archivo de log de autenticación (auth.log o secure)."
        exit 1
    fi
}

process_logs() {
    # Procesa los logs para obtener usuarios, PID e IP de sesiones activas.
    # Se usa 'sshd' y 'dropbear' para obtener sesiones activas.
    
    # Reiniciar servicios (Solo si es necesario al principio, se mantiene por estructura original)
    service sshd restart > /dev/null 2>&1
    service dropbear restart > /dev/null 2>&1

    # 1. Obtener todos los usuarios con home directory
    cat /etc/passwd | grep "/home/" | cut -d":" -f1 > /tmp/user.txt
    
    # Usar arrays asociativos para mejor manejo de datos
    declare -A user_count # Conteo de logins por usuario
    declare -A user_ips   # IPs de logins por usuario

    # Función auxiliar para parsear logs (más eficiente que el método original con grep y bucles anidados)
    # SSHD: Busca "Accepted password for USER from IP"
    awk '/Accepted password for/ { 
        user=$9; ip=$11; 
        if (user in count) { count[user]++; ips[user] = ips[user] " | " ip } 
        else { count[user]=1; ips[user]=ip } 
    } END { 
        for (u in count) print u, count[u], ips[u] 
    }' $LOG | while read -r user count_val ips_val; do
        user_count[$user]=$count_val
        user_ips[$user]=$ips_val
    done

    # DROPBEAR: Busca "Password auth succeeded for USER on IP"
    awk '/Password auth succeeded/ {
        # Esto puede variar, asumimos que el usuario es el campo 10 y la IP el 12.
        user=$10; ip=$12; 
        # Limpiar comillas simples
        user=gensub(/\x27/,"","g",user); 
        ip=gensub(/\x27/,"","g",ip); 
        
        if (user in count) { count[user]++; ips[user] = ips[user] " | " ip } 
        else { count[user]=1; ips[user]=ip } 
    } END { 
        for (u in count) print u, count[u], ips[u]
    }' $LOG | while read -r user count_val ips_val; do
        # Combinar resultados (sumar conteos y concatenar IPs si ya existía el usuario en SSHD)
        if [[ -v user_count[$user] ]]; then
            user_count[$user]=$(( user_count[$user] + count_val ))
            user_ips[$user]="${user_ips[$user]} | ${ips_val}"
        else
            user_count[$user]=$count_val
            user_ips[$user]=$ips_val
        fi
    done
    
    # Devolvemos las variables de conteo y IPs al ámbito global
    for user in "${!user_count[@]}"; do
        echo "$user ${user_count[$user]}"
    done > /tmp/ssh_user_counts

    for user in "${!user_ips[@]}"; do
        echo "$user ${user_ips[$user]}"
    done > /tmp/ssh_user_ips

    # Limpieza: el script original eliminaba el log de auth.log para el usuario
    # sed -i "/${username[$i]}/d" /var/log/auth.log 
    # Mantenemos esta lógica al final del script principal si se detecta multi-login.
}


# ===============================================
# 3. EJECUCIÓN PRINCIPAL
# ===============================================

checking_sc
get_log_source

# Limpieza inicial de archivos temporales
rm -rf /tmp/ssh /tmp/log-db.txt /tmp/log-db-pid.txt /tmp/user.txt
clear

# Lógica de seguridad para procesos bash excesivos
bash2=$( pgrep bash | wc -l )
if [[ $bash2 -gt "20" ]]; then
    # PRECAUCIÓN: Esto puede matar procesos legítimos.
    killall bash
fi

# Llama a la función de procesamiento de logs
process_logs

# Iterar sobre los conteos de usuarios
while read -r user total_logins; do
    limitip=$(cat "/etc/xray/sshx/${user}IP" 2>/dev/null)
    # Si no hay límite definido, se salta o se asigna un valor por defecto (se asume que se salta si no existe el archivo)
    if [[ -z $limitip ]]; then
        continue
    fi

    # Comprobación de límite de IP
    if [[ $total_logins -gt $limitip ]]; then
        
        # 1. Registrar y preparar notificaciones
        date=`date +"%Y-%m-%d %X"`
        echo "$date - ${user} - ${total_logins}" >> "/etc/xray/sshx/${user}login"
        
        sship=$(cat "/etc/xray/sshx/${user}login" | wc -l)
        sship2=$(cat /tmp/ssh_user_ips | grep -w "$user" | cut -d ' ' -f 2- | sed 's/ | /\n/g' | nl -s '. ')
        
        ssssh1=$(ls "/etc/xray/sshx" | grep -w "notif")
        ssssh="3"
        if [[ ! -z ${ssssh1} ]]; then
            ssssh=$(cat /etc/xray/sshx/notif)
        fi

        # 2. Enviar notificación inicial (al primer exceso)
        if [ $sship -eq 1 ]; then
            TEXT="
<code>◇━━━━━━━━━━━━━━━━◇</code>
<b> ⚠️ SSH NOTIF MULTI LOGIN</b>
<code>◇━━━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${domen} </b>
<b>ISP : ${ISP}</b>
<b>CITY : $CITY</b>
<b>DATE LOGIN : $DATE</b>
<b>USERNAME : ${user} </b>
<b>TOTAL LOGIN IP : ${total_logins} </b>
<code>◇━━━━━━━━━━━━━━━━◇</code>
<b>TIME LOGIN : IP LOGIN </b>
<code>$sship2</code>
<code>◇━━━━━━━━━━━━━━━━◇</code>
<i>${sship}x Multi Login : ${ssssh}x Multi Login Auto Lock Account...</i>
"
            sed -i "/${user}/d" /var/log/auth.log
            curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
        fi


        # 3. Aplicar acción de bloqueo/eliminación (cuando alcanza el límite de notificaciones)
        if [ $sship -ge $ssssh ]; then
            
            exp=$(grep -i "### ${user}" "/etc/xray/ssh" | cut -d ' ' -f 3 | sort | uniq)
            pass=$(grep -i "### ${user}" "/etc/xray/ssh" | cut -d ' ' -f 4 | sort | uniq)
            
            # Notificación de BLOQUEO/ELIMINACIÓN
            TEXT2="
<code>◇━━━━━━━━━━━━━━━━◇</code>
<b> ⚠️ SSH NOTIF MULTI LOGIN</b>
<code>◇━━━━━━━━━━━━━━━━◇</code>
<b>DOMAIN : ${domen} </b>
<b>ISP : ${ISP}</b>
<b>CITY : $CITY</b>
<b>USERNAME : ${user} </b>
<b>TOTAL LOGIN IP : ${total_logins} </b>
<code>◇━━━━━━━━━━━━━━━━◇</code>
<b>TIME LOGIN : IP LOGIN </b>
<code>$sship2</code>
<code>◇━━━━━━━━━━━━━━━━◇</code>
<i>${ssssh}x Multi Login Auto Lock Account...</i>
"
            sed -i "/${user}/d" /var/log/auth.log
            curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT2&parse_mode=html" $URL >/dev/null
            
            # Bloqueo de la cuenta
            echo "### ${user} $exp $pass" >> /etc/xray/sshx/listlock
            passwd -l ${user}
            
            # Lógica Delete vs Lock
            if [ "$type" = "delete" ]; then
                sed -i "/^### ${user} $exp $pass/d" /etc/xray/ssh # Elimina de la lista de usuarios activos
                # No se requiere reiniciar servicios por 'passwd -l', pero sí por el manejo de sesiones.
            elif [ "$type" = "lock" ]; then
                cat > /etc/cron.d/ssh${user} << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/$waktulock * * * * root /usr/bin/xray ssh ${user} $pass $exp
EOF
                systemctl restart cron > /dev/null 2>&1
            fi
            
            # Limpieza y reinicios de servicios relacionados con proxy/túnel (ws-stunnel, ws-dropbear)
            rm -rf "/etc/xray/sshx/${user}login"
            systemctl restart ws-stunnel > /dev/null 2>&1
            systemctl restart ws-dropbear > /dev/null 2>&1

        fi
    fi
done < /tmp/ssh_user_counts

# Limpieza final
rm -rf /tmp/ssh_user_counts /tmp/ssh_user_ips
