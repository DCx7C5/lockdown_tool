#!/usr/bin/env bash

set -o errexit
set -o pipefail

if [ "$EUID" -ne 0 ];then
  echo "Please run as root"
  exit
fi

trap on_proc_interrupt SIGHUP SIGINT SIGTERM #EXIT

BRED="\e[1;31m"
BGREEN="\e[1;32m"
BYELLOW="\e[1;33m"
ENDC="\e[0m"

APP_NAME='lockdown'
AUTHOR="@dcx7c5"
MODPROBE_DIR=/etc/modprobe.d/
SETTINGS_DIR=/etc/${APP_NAME}/

DEFAULT_SETTINGS_FILE=${SETTINGS_DIR}defaults.conf

CFG_SYSCTL=/etc/sysctl.d/${APP_NAME}_hardening.conf
CFG_MP_NETPROT=${MODPROBE_DIR}30_${APP_NAME}_network_protocols.conf
CFG_MP_FS=${MODPROBE_DIR}30_${APP_NAME}_filesystems.conf
CFG_MP_NETFS=${MODPROBE_DIR}30_${APP_NAME}_network_filesystems.conf
CFG_MP_MISC=${MODPROBE_DIR}30_${APP_NAME}_misc.conf

ALL_CFG_PATHS="$CFG_SYSCTL $CFG_MP_NETPROT $CFG_MP_FS $CFG_MP_NETFS $CFG_MP_MISC $DEFAULT_SETTINGS_FILE"

logtofile() {
  echo "$(date +"%Y-%m-%d %H:%M:%S") | $1" >> /var/log/lockdown.log 2>&1 &
}

shutdown() {
  logtofile 'EXIT | Exiting Lockdown Tool.'
  exit 0
}

cleanup() {
  clear
  [[ -d /tmp/lockdown ]] && rm -rf /tmp/lockdown >/dev/null
}

on_proc_interrupt() {
  logtofile 'ERROR | ...SIGINT received, cleaning up'
  cleanup
  shutdown
}

header() {
  local txt mnl theight="$1"
  for x in $(seq 1 "$((theight-17))"); do mnl+="\n"; done
  txt="
.____                  __       .___
|    |    ____   ____ |  | __ __| _/______  _  ______
|    |   /  _ \_/ ___\|  |/ // __ |/  _ \ \/ \/ /    \    lockdown - hardening tool
|    |__(  <_> )  \___|    </ /_/ (  <_> )     /   |  \   by ${AUTHOR}
|_______ \____/ \___  >__|_ \____ |\____/ \/\_/|___|  /
        \/          \/     \/    \/                 \/


"
  printf "$mnl%s" "$txt"
}

cfg_file_check() {
  local cfg_path="$1"
  if [[ ! -f $cfg_path ]]; then
    logtofile "SETUP | Config file not found or empty: $cfg_path"
    return 1
  fi
  return 0
}

create_cfg_file() {
  local x cfg cfg_path="$1"
  if [[ $cfg_path == */defaults.conf ]]; then
    [[ ! -d $SETTINGS_DIR ]] && mkdir "$SETTINGS_DIR"
    echo "# LOCKDOWN SYSCTL DEFAULTS" | tee "$cfg_path" >/dev/null
    while read -r x; do
      cfg=$(echo "$x"| cut -d ',' -f2)
      echo "#$(sysctl "$cfg")" | tee -a "$cfg_path" >/dev/null
    done <templates/recommended_sysctl.conf
    sed -i 's/\ \=\ /\=/;s/\t/\ /g' "$cfg_path"
    chmod 600 "$cfg_path"
  elif [[ $cfg_path == *hardening.conf ]]; then
    touch "$cfg_path"
    while read -r x; do
      cfg=$(echo "$x"| cut -d ',' -f2)
      rval=$(echo "$x"| cut -d ',' -f3)
    echo "#$cfg=$rval" | tee -a "$cfg_path" >/dev/null
    done <templates/recommended_sysctl.conf
    chmod 644 "$cfg_path"
  elif [[ $cfg_path == *modprobe* ]]; then
    file=$(echo "$cfg_path"| cut -d'/' -f4)
    cp "templates/$file" "$cfg_path"
    chmod 644 "$cfg_path"
  fi
  chown root:root "$cfg_path"
  logtofile "SETUP | Created config file: $cfg_path"
}

help() {
  clear
  echo "Usage: lockdown.sh                 # run interactive
                              -h | --help   # show this help message"
}

create_project_arrays() {
  local line ks info rval dval state
  declare -Ag lkm_arr sysctl_arr
  declare -ag sysc_name_arr

  while read -r line; do
    name=$(echo "$line"| sed 's/#install\ //;s/\ \/bin\/false//')
    lkm_arr[$name]=$CFG_MP_NETPROT
    lkm_arr[$CFG_MP_NETPROT]+="$name "
  done <templates/30_lockdown_network_protocols.conf

  while read -r line; do
    name=$(echo "$line"| sed 's/#install\ //;s/\ \/bin\/false//')
    lkm_arr[$name]=$CFG_MP_FS
    lkm_arr[$CFG_MP_FS]+="$name "
  done <templates/30_lockdown_filesystems.conf

  while read -r line; do
    name=$(echo "$line"| sed 's/#install\ //;s/\ \/bin\/false//')
    lkm_arr[$name]=$CFG_MP_NETFS
    lkm_arr[$CFG_MP_NETFS]+="$name "
  done <templates/30_lockdown_network_filesystems.conf

  while read -r line; do
    name=$(echo "$line"| sed 's/#install\ //;s/\ \/bin\/false//')
    lkm_arr[$name]=$CFG_MP_MISC
    lkm_arr[$CFG_MP_MISC]+="$name "
  done <templates/30_lockdown_misc.conf

  while read -r line; do
    info=$(echo "$line"| cut -d',' -f1)
    ks=$(echo "$line"| cut -d',' -f2)
    rval=$(echo "$line"| cut -d',' -f3)
    ks_line=$(grep "$ks" "$CFG_SYSCTL")
    dval=$(grep "#$ks" "$DEFAULT_SETTINGS_FILE"| cut -d'=' -f2)
    if [[ $rval == "$dval" ]]; then
      state="default,is hardened"
    elif [[ rval != "$dval" ]] && [[ '#' == "${ks_line:0:1}" ]];then
      state="not hardened"
    elif [[ rval != "$dval" ]] && [[ ! '#' == "${ks_line:0:1}" ]];then
      state="is hardened"
    else
      state="not hardened"
    fi
    sysctl_arr[$ks]="$info|$rval|$dval|$state"
    sysc_name_arr+=("$ks")
  done <templates/recommended_sysctl.conf

  logtofile "INIT | ... arrays created & filled"
}

init_routine() {
  logtofile "INIT | Starting lockdown hardening and privacy tool"
  for cfg in $ALL_CFG_PATHS; do
    if ! cfg_file_check "$cfg"; then
      create_cfg_file "$cfg"
    fi
  done
  create_project_arrays
}

lkm_is_blacklisted() {
  local lkm="$1"
  lkm_line=$(grep "$lkm" "${lkm_arr[$lkm]}")
  if [[ -z $lkm_line ]]; then
    echo "# install $lkm /bin/false" | tee -a "${lkm_arr[$lkm]}" &
    return 1
  elif [[ "#" == "${lkm_line:0:1}" ]]; then
    return 1
  fi
  return 0
}

set_sysctl_hardening_state() {
  local ks="$1" rval ks_line dval state
  state=$(echo "${sysctl_arr[$ks]}"| cut -d'|' -f4)
  rval=$(echo "${sysctl_arr[$ks]}"| cut -d'|' -f2)
  dval=$(echo "${sysctl_arr[$ks]}"| cut -d'=' -f3)
  if [[ $state == 'default,is hardened' ]]; then
    sysctl_arr[$ks]="$(echo "${sysctl_arr[$ks]}"| cut -d'|' -f'1 2 3')|file,is hardened"
    sed -i "s/#$ks/$ks/" "$CFG_SYSCTL" >/dev/null
    logtofile "SYSCTL | default cfg overwrite @ $ks=$rval"
  elif [[ $state == 'not hardened' ]];then
    sysctl_arr[$ks]="$(echo "${sysctl_arr[$ks]}"| cut -d'|' -f'1 2 3')|is hardened"
    sed -i "s/#$ks/$ks/" "$CFG_SYSCTL" >/dev/null
    sysctl -w "$ks=$rval" >/dev/null &
    logtofile "SYSCTL | hardened settings @ $ks=$rval"
  elif [[ $state == 'is hardened' ]];then
    sysctl_arr[$ks]="$(echo "${sysctl_arr[$ks]}"| cut -d'|' -f'1 2 3')|not hardened"
    sed -i "s/$ks/#$ks/" "$CFG_SYSCTL" >/dev/null
    sysctl -w "$ks=$dval" >/dev/null &
    logtofile "SYSCTL | set to default @ $ks=$dval"
  elif [[ $state == 'file,is hardened' ]]; then
      sysctl_arr[$ks]="$(echo "${sysctl_arr[$ks]}"| cut -d'|' -f'1 2 3')|default,is hardened"
      sed -i "s/$ks/#$ks/" "$CFG_SYSCTL" >/dev/null
      logtofile "SYSCTL | default cfg restored @ $ks=$rval"
  fi
}

get_ks_state_colored() {
  local ks="$1"
    state=$(echo "${sysctl_arr[$ks]}"| cut -d'|' -f4)
  if [[ $state == 'default,is hardened' ]]; then
    echo "default,${BGREEN}is hardened${ENDC}"
  elif [[ $state == 'not hardened' ]];then
    echo "${BRED}not hardened${ENDC}"
  elif [[ $state == 'is hardened' ]];then
    echo "${BGREEN}is hardened${ENDC}"
  elif [[ $state == 'file,is hardened' ]]; then
    echo "${BGREEN}is hardened${ENDC}"
  fi
}

build_kloak() {
  BLDDIR="/tmp/kloak"
  if [[ -d "$BLDDIR" ]]; then rm -rf "$BLDDIR" 2>/dev/null; fi
  git clone "https://github.com/vmonaco/kloak" "$BLDDIR" && cd "$BLDDIR" || exit 1
  make all
  cp ./eventcap /usr/sbin/
  cp ./kloak /usr/sbin/
  logtofile "KLOAK | ... build successful"
}

install_kloak_service() {
  cp templates/kloak.service /etc/systemd/system/kloak.service
  systemctl daemon-reload
  systemctl enable kloak.service
  systemctl start kloak.service
  if [[ -d "/etc/apparmor.d/" ]]; then
    PATH="https://raw.githubusercontent.com/DCx7C5/debian_hardening/development/apparmor.d/usr.sbin.kloak"
    wget -O /etc/apparmor.d/usr.sbin.kloak "$PATH" >/dev/null 2>&1
  fi
  logtofile "KLOAK | ... installed as service"
}

kloak_is_installed() {
  if [[ -f /etc/systemd/system/kloak.service ]]; then
    return 0
  else
    return 1
  fi
}

kloak_is_active() {
  if [[ 'active' == $(systemctl is-active kloak.service) ]]; then
    return 0
  else
    return 1
  fi
}

install_or_start_kloak() {
  if ! kloak_is_installed; then
    build_kloak
    install_kloak_service
  elif kloak_is_installed && ! kloak_is_active; then
    systemctl start kloak.service >/dev/null
  fi
}

# shellcheck disable=SC2120
screen_prompt() {
  if [[ -z $1 ]]; then
    printf "$BGREEN%s$ENDC > " "$APP_NAME"
  else
    printf "$BGREEN%s$ENDC($BYELLOW$1$ENDC) > " "$APP_NAME"
  fi
}

main_menu() {
  local ans mnl menu
  local -i theight
  theight=$(($(tput lines)-1))
  menu="
1) Sysctl Hardening Menu
2) Kernel Module Blacklisting
3) additional hardening methods
0) Exit"
  clear
  header "$theight"
  printf "Main Menu\n%s\n\n\n" "$menu"
  screen_prompt
  read -r ans
  case $ans in
    1|sysctl) ksettings_menu;;
    3|extras) extras_menu;;
    0|exit) cleanup; shutdown;;
    *) main_menu;;
  esac
}


extras_menu() {
  local ans mnl menu state
  local -i theight
  theight=$(($(tput lines)-1))
  clear
  header $theight
  if kloak_is_installed; then state="${BGREEN}installed${ENDC} | "; else state="${BRED}not installed${ENDC} | "; fi
  if kloak_is_active; then state+="${BGREEN}running${ENDC}"; else state+="${BRED}not running${ENDC}"; fi
  printf "$%-30s\t\t$state\n\n\n\n\n\n\n%s\n\n" "1) Install/Start Kloak module" "0) back to main menu"
  screen_prompt "extras"
  read -r ans
  case $ans in
    1) install_or_start_kloak;extras_menu;;
    0) main_menu;;
    *) extras_menu;;
  esac
}


ksettings_menu() {
  local ans l elem info re line state cstate menu_str
  local -i elemc count space theight
  elemc="${#sysctl_arr[@]}"
  theight=$(tput lines)
  count=1
  clear
  echo -ne "\n\n"
  for l in ${sysc_name_arr[*]}; do
    elem="${sysctl_arr[$l]}"
    info=$(echo "$elem"| cut -d'|' -f1)
    state=$(echo "$elem"| cut -d'|' -f4)
    cstate=$(get_ks_state_colored "$l")
    if ((count < 10)); then space=51; else space=50; fi
    menu_str+=$(printf "\n$count) $BYELLOW%-${space}s$ENDC | %-45s | $cstate" "$info" "$l")
    count=$(("$count"+1))
  done
  printf "%s\n\n" "$menu_str"
  printf "%s\n%s\n\n" "n) harden setting / load default" "0) back to Main Menu"
  screen_prompt "sysctl"
  read -r ans
  for n in $(seq 1 "$elemc"); do re+="|^$n$"; done
  if [[ $ans == "0" ]]; then
    main_menu
  elif [[ $ans == "back" ]]; then
    main_menu
  elif [[ $ans == "exit" ]]; then
    cleanup
    shutdown
  elif [[ $ans =~ $re ]]; then
    set_sysctl_hardening_state "${sysc_name_arr[ans-1]}"
    ksettings_menu
  else
    ksettings_menu
  fi
}

main() {
  if [[ $# -eq 0 ]]; then
    init_routine
    main_menu
  fi
  if [[ $# -gt 1 ]]; then
    help
    echo "Error: Only one argument allowed"
    exit 2
  fi
  case $1 in
    -h | --help) help; exit 2;;
    *) help; exit 2;;
  esac
}

main "$@"