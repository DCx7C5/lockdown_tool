#!/usr/bin/env bash

set -o errexit
set -o nounset
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

logtofile () {
  echo "$(date +"%Y-%m-%d %H:%M:%S") | $1" >> /var/log/lockdown.log 2>&1 &
}

shutdown () {
  logtofile 'Exiting Lockdown Tool.'
  exit 0
}

cleanup () {
  clear
  [[ -d /tmp/lockdown ]] && rm -rf /tmp/lockdown >/dev/null
}

on_proc_interrupt () {
  logtofile '...SIGINT received, cleaning up'
  cleanup
  shutdown
}

cfg_file_check () {
  local cfg_path="$1"
  if [[ ! -f $cfg_path ]]; then
    logtofile "Config file not found or empty: $cfg_path"
    return 1
  fi
  return 0
}

create_cfg_file () {
  local x cfg cfg_path="$1"
  if [[ $cfg_path == */defaults.conf ]]; then
    [[ ! -d $SETTINGS_DIR ]] && mkdir "$SETTINGS_DIR"
    echo "# LOCKDOWN SYSCTL DEFAULTS" | tee "$cfg_path" >/dev/null
    while read -r x; do
      cfg=$(echo "$x"| cut -d ',' -f2)
      echo "#$(sysctl "$cfg")" | tee -a "$cfg_path" >/dev/null &
    done < "templates/recommended_sysctl.conf"
    sed -i 's/\ \=\ /\=/;s/\t/\ /g' "$cfg_path"
    chmod 600 "$cfg_path"
  elif [[ $cfg_path == *hardening.conf ]]; then
    touch "$cfg_path"
    chmod 644 "$cfg_path"
  elif [[ $cfg_path == *modprobe* ]]; then
    touch "$cfg_path"
    chmod 644 "$cfg_path"
  fi
  chown root:root "$cfg_path"
  logtofile "Created config file: $cfg_path"
}

help () {
  clear
  echo "Usage: lockdown.sh                 # run interactive
                              -h | --help   # show this help message"
}

create_project_arrays () {
  local line ks info mpnetlst mpfslst mpnetfslst mpmisclst rval dval
  declare -Ag lkm_arr sysctl_arr
  declare -ag sysc_name_arr

  mpnetlst="dccp sctp rds tipc n-hdlc ax25 netrom x25 rose decnet econet af_802154 ipx appletalk psnap p8023 p8022 can atm"
  mpfslst="cramfs freevxfs jffs2 hfs hfsplus squashfs udf"
  mpnetfslst="cifs nfs nfsv3 nfsv4 ksmbd gfs2"
  mpmisclst="vivid bluetooth btusb uvcvideo"

  for name in $mpnetlst; do lkm_arr[$name]=$CFG_MP_NETPROT; done
  for name in $mpfslst; do lkm_arr[$name]=$CFG_MP_FS; done
  for name in $mpnetfslst; do lkm_arr[$name]=$CFG_MP_NETFS; done
  for name in $mpmisclst; do lkm_arr[$name]=$CFG_MP_MISC; done

  lkm_arr[$CFG_MP_MISC]=$mpmisclst
  lkm_arr[$CFG_MP_NETFS]=$mpnetfslst
  lkm_arr[$CFG_MP_FS]=$mpfslst
  lkm_arr[$CFG_MP_NETPROT]=$mpnetlst

  while read -r line; do
    info=$(echo "$line"| cut -d',' -f1)
    ks=$(echo "$line"| cut -d',' -f2)
    rval=$(echo "$line"| cut -d',' -f3)
    dval=$(grep "$ks" "$DEFAULT_SETTINGS_FILE"| cut -d'=' -f2)
    sysctl_arr[$ks]="$info|$rval|$dval"
    sysc_name_arr+=("$ks")
  done < "templates/recommended_sysctl.conf"
  logtofile "INIT | ... arrays initialized"
}

init_routine () {
  logtofile "Starting lockdown hardening and privacy tool"
  for cfg in $ALL_CFG_PATHS; do
    if ! cfg_file_check "$cfg"; then
      create_cfg_file "$cfg"
    fi
  done
  create_project_arrays
}

lkm_is_blacklisted () {
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

set_sysctl_hardening_state () {
  local ks="$1" rval ks_line dval
  if ks_is_hardened "$ks"; then
    ks_line=$(grep "$ks" "$DEFAULT_SETTINGS_FILE")
    dval="$(echo "$ks_line"| cut -d'=' -f2)"
    sed -i "s/$ks/#\ $ks/" "$CFG_SYSCTL" >/dev/null &
    sysctl -w "$ks=$dval" >/dev/null &
    logtofile "SYSCTL | set to default @ $ks=$dval"
  else
    rval=$(echo "${sysctl_arr[$ks]}" | cut -d'|' -f2)
    sed -i "s/#\ $ks/$ks/" "$CFG_SYSCTL" >/dev/null &
    sysctl -w "$ks=$rval" >/dev/null &
    logtofile "SYSCTL | hardened settings @ $ks=$rval"
  fi
}

ks_is_hardened () {
  local ks="$1" ks_line ks_rec
  ks_line=$(grep "$ks" "$CFG_SYSCTL")
  ks_rec=$(echo "${sysctl_arr[$ks]}"| cut -d'|' -f2)
  liveval=$(sysctl "$ks" | cut -d'=' -f2)
  if [[ -z $ks_line ]]; then
    echo "# $ks=$ks_rec" | tee -a "$CFG_SYSCTL" >/dev/null &
    return 1
  elif [[ '#' == "${ks_line:0:1}" ]]; then
    return 1
  elif [[ $ks_rec == "$liveval" ]]; then
    return 0
  fi
  return 0
}

build_kloak () {
  BLDDIR="/tmp/kloak"
  if [[ -d "$BLDDIR" ]]; then rm -rf "$BLDDIR" 2>/dev/null; fi
  git clone "https://github.com/vmonaco/kloak" "$BLDDIR" && cd "$BLDDIR" || exit 1
  make all
  cp ./eventcap /usr/sbin/
  cp ./kloak /usr/sbin/
  logtofile "KLOAK | ... build successful"
}

install_kloak_service () {
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

kloak_is_installed () {
  if [[ -f /etc/systemd/system/kloak.service ]]; then
    return 0
  else
    return 1
  fi
}

kloak_is_active () {
  if [[ 'active' == $(systemctl is-active kloak.service) ]]; then
    return 0
  else
    return 1
  fi
}

install_or_start_kloak () {
  if ! kloak_is_installed; then
    build_kloak
    install_kloak_service
  elif kloak_is_installed && ! kloak_is_active; then
    systemctl start kloak.service >/dev/null
  fi
}

main_menu () {
  local ans mnl menu
  local -i theight
  theight=$(($(tput lines)-1))
  mnl=""
  for x in $(seq 1 "$((theight-5))"); do mnl+="\n"; done
  menu="
1) Sysctl Hardening Menu
2) Kernel Module Blacklisting
3) additional hardening methods
0) Exit"
  clear
  printf "${mnl}Main Menu\n%s\n\n\n" "$menu"
  printf "$BGREEN%s$ENDC> " "$APP_NAME"
  read -r ans
  case $ans in
    1|sysctl) ksettings_menu;;
    3|extras) extras_menu;;
    0|exit) cleanup; shutdown;;
    *) main_menu;;
  esac
}

extras_menu () {
  local ans mnl menu kloak_state
  local -i theight
  theight=$(($(tput lines)-1))
  mnl=""
  kloak_state=""
  clear
  for x in $(seq 1 "$((theight-3))"); do mnl+="\n"; done
  if kloak_is_installed;then kloak_state+="${BGREEN}installed${ENDC} | ";else kloak_state+="${BRED}not installed${ENDC} | ";fi
  if kloak_is_active;then kloak_state+="${BGREEN}running${ENDC}";else kloak_state+="${BRED}not running${ENDC}";fi
  printf "${mnl}%-30s\t\t$kloak_state\n\n%s\n\n" "1) Install/Start Kloak module" "0) back to main menu"
  printf "${BGREEN}%s${ENDC}(${BYELLOW}extras${ENDC})> " "$APP_NAME"
  read -r ans
  case $ans in
    1) install_or_start_kloak;extras_menu;;
    0) main_menu;;
    *) extras_menu;;
  esac
}

ksettings_menu () {
  local ans l elem info re line
  local -i elemc count space theight
  elemc="${#sysctl_arr[@]}"
  theight=$(tput lines)
  count=1
  mnl=""
  clear
  for x in $(seq 1 "$((theight-elemc))"); do mnl+="\n"; done
  echo -ne "$mnl"
  for l in ${sysc_name_arr[*]}; do
    elem="${sysctl_arr[$l]}"
    info=$(echo "$elem"| cut -d'|' -f1)
    if ks_is_hardened "$l"; then val="${BGREEN}is hardened${ENDC}" ; else val="${BRED}not hardened${ENDC}"; fi
    if ((count < 10)); then space=51; else space=50; fi
    printf "$count) $BYELLOW%-${space}s$ENDC | %-45s | $val\n" "$info" "$l"
    count=$(("$count"+1))
  done
  printf "\n%s\n%s\n" "n) harden setting / load default" "0) back to Main Menu"
  printf "\n${BGREEN}%s${ENDC}(${BYELLOW}sysctl${ENDC})> " "$APP_NAME"
  read -r ans
  re="^1$"
  for n in $(seq 2 "$elemc"); do re+="|^$n$"; done
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



main () {
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