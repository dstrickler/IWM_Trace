#!/bin/bash
#
# ---------------------------------------------------------------------------
# DStrickler Sep 12, 2014
# Code has been altered to use curl to get/put data via a web-based API
# instead of by FTP, as the FTP servers prooved too hard to load balance
# as IWM grew in size.
#
# DStrickler Sep 14, 2014
# Thanks to MBrandon for beta testing and pushing me to get on GitHub.
# ---------------------------------------------------------------------------
#
# This is your Tracer Key. Make sure this is unique for each bash file you run.
# Additional keys can be generated from our portal: www.internetweathermap.com
KEY="replace_with_your_personal_key"
#
# This is the 5-minute load average threshold
# If this system is running above this load average, IWM run will be skipped
HIGHLOAD="5"
#
# Report runtime into syslog when run from cron, 1=yes
REPORT="1"


################################
# DO NOT EDIT BEYOND THIS LINE #
################################
VERSION="4.0.018"
IWMHOST="api.internetweathermap.com"
IWMDIR="iwm"
IWMPROTO="http"
LOGGER="-i -p INFO -t iwm"
# (original) CURL="--retry 5 --retry-delay 1 -s -B -u ${USER}:${PASS}"
# -s = Silent mode,
CURL="--retry 5 --retry-delay 1 -s"
HOPS="15"
TRACE="-n -m ${HOPS}"

get_unixtime() {
    echo $(date +%s.%3N)
    }

get_timestamp_now() {
    echo $(date +"%m-%d-%Y %H:%M:%S")
}

info() {
 if (( ${CRON} == 1 )); then
   type -p logger > /dev/null 2>&1
   if (( ${?} == 0 )); then
     logger ${LOGGER} "${1}"
   fi
 else
   echo "${1}"
 fi
}

error() {
 loadavg=$(get_loadavg)
 timestamp_now=$(get_timestamp_now)
 info "${timestamp_now} :: ${loadavg} :: [!] Test cancelled: ${1}"
 (( ${2} == 1 )) && exit 1
}

check_exitcode() {
 if (( ${RETVAL} == 0 )); then
   info "OK"
 else
   info "FAILED"
 fi
}

get_loadavg() {
 # In Linux systems, get load average directly from /proc
 # Others: try to use uptime and be flexible on the format (different uptime implementations)
 if [[ -f /proc/loadavg ]]; then
   awk '{ print $2 }' /proc/loadavg
 else
   uptime | sed 's/\(.*\)load average\(.*\) \(.*\) \(.*\)/\3/g'
 fi
}

# These are defined over again inside of any loop
loadavg=$(get_loadavg)
timestamp_now=$(get_timestamp_now)

# Figure out where traceroute lives, and set it as a var for use later.
if [ -e "/usr/bin/traceroute" ]; then
    TRACEROUTE_PATH="/usr/bin/traceroute"
fi
if [ -e "/usr/sbin/traceroute" ]; then
    # Configuration for OSX
    TRACEROUTE_PATH="/usr/sbin/traceroute"
fi
if [ -e "/bin/traceroute" ]; then
    TRACEROUTE_PATH="/bin/traceroute"
fi

# If we don't have one of these programs, halt, and let the user know.
# The traceroute command can't be found on OSX, so I removed it from the test.
for cmd in awk bc date curl logger mkdir sed tty uptime
do
 type -p ${cmd} > /dev/null 2>&1
 if (( ${?} == 1 )); then
   error "Mandatory command (${cmd}) for IWM not found. Please install." 1
 fi
done

# Try and create a temp directory. If not, exit and clean up the lock file.
IWMTMPDIR=$(mktemp -d /tmp/tmp.XXXXXXXXXX)
[[ -d ${IWMTMPDIR} ]] || \
 error "Could not create temp directory ${IWMTMPDIR}." 1 && \
 trap "rm -rf ${IWMTMPDIR} ${LOCKFILE}" EXIT

mkdir ${IWMTMPDIR}/output


# Run a check to see if there is a new version of the code.
# If so, replace the code we are currently running.
VERSION_FILE="${IWMTMPDIR}/iwm_trace_bash_version.txt"
CURLURL="${IWMPROTO}://${IWMHOST}/api/get_iwm_trace_bash_version"
curl -o ${VERSION_FILE} -s --url "${CURLURL}"
current_version=`cat ${VERSION_FILE}`
# echo "${timestamp_now} :: ${loadavg} :: Latest version of this bash code is: ${current_version}"
if [[ "${current_version}" == "${VERSION}" ]] ; then
    echo "${timestamp_now} :: ${loadavg} :: This is the most current version of this software: ${VERSION}"
else
    path_to_bash="${0}"
    echo "${timestamp_now} :: ${loadavg} :: This verison needs to be upgraded from '${VERSION}' to '${current_version}'."
    echo "${timestamp_now} :: ${loadavg} :: Saving version ${current_version} to ${path_to_bash}"
    CURLURL="${IWMPROTO}://${IWMHOST}/api/get_iwm_trace_bash_code/${KEY}"
    curl -o "${path_to_bash}"  -s --url "${CURLURL}"
    chmod +x ${path_to_bash}
    echo "${timestamp_now} :: ${loadavg} :: Halting current code so it runs the new version when run again."
    if [[ -e "/var/lock/iwm.loc" ]]; then
        rm /var/lock/iwm.loc
    fi
    if [[ -e "/tmp/iwm.lock" ]]; then
        rm /tmp/iwm.lock
    fi
    exit
fi

# Find out a existing directory that's writable.
# If all else fails, use your home directory.
# TODO: On servers like Webfaction, this lock will FAIL
LOCKFILE="~/iwm.lock"
if [[ -d '/var/lock'  &&  -w '/var/lock' ]]; then
    LOCKFILE="/var/lock/iwm.lock"
fi
if [[ -d '/tmp'  &&  -w '/tmp' ]]; then
    LOCKFILE="/tmp/iwm.lock"
fi
# echo "Using lock file: ${LOCKFILE}"

# If the lock file is too old, delete it.
if [[ -e ${LOCKFILE} ]]; then
    if [ "$(find ${LOCKFILE} -mmin +1)" != "" ]; then
        echo "${timestamp_now} :: ${loadavg} :: Lockfile ${LOCKFILE} is more than a minute old - stale - delete it."
        rm ${LOCKFILE}
    else
        echo "${timestamp_now} :: ${loadavg} :: Lockfile (${LOCKFILE}) is too fresh to run."
    fi
fi

# TODO: Trap for an O/S to get a better understanding of the environment.
# We might trap for an O/S at a later date.
# OS=$(uname -s 2>/dev/null)
# echo "${OS}"


CRON=0
if [[ -e ${LOCKFILE} ]]; then
    error "Previous test still on-going due to recent lock file found at ${LOCKFILE}" 1
fi


# Put the datestamp into the lock file so we know when it was locked.
# echo "Creating the lock file: ${LOCKFILE}"
start=$(get_unixtime)
echo "${start}" > ${LOCKFILE}


# Find out if we are being run from the CLI or CRON.
tty -s
(( ${?} == 1 )) && CRON="1"

WORKLIST=${IWMTMPDIR}/worklist.${KEY}
OUTDIR=${IWMTMPDIR}/output

(( ${CRON} == 0 )) && echo -n "${timestamp_now} :: ${loadavg} :: Fetching new worklist: "

# Get a worklist from the API. Easy, quick and reliable.
CURLURL="${IWMPROTO}://${IWMHOST}/api/get_worklist/${KEY}"
curl -o ${WORKLIST} -s --url "${CURLURL}"
RETVAL=$?
stopone=$(get_unixtime)
check_exitcode "Fetching new worklist"
[[ -s ${WORKLIST} ]] || error "Worklist file is empty" 1


for ip in $(cat ${WORKLIST})
do
 loadavg=$(get_loadavg)
 (( $(bc <<< "${loadavg} >= ${HIGHLOAD}") == 1 )) && \
   error "5-minute load average ${loadavg} is TOO HIGH" 1

    # Unclear what this does.
    # TODO: Figure out why this was put in here. Can it be removed?
    timestamp="$(get_unixtime)"
    while [[ -f ${OUTDIR}/${timestamp}.${KEY} ]]; do
       timestamp="$(get_unixtime)"
    done

 TRACEIP=$(echo ${ip} | sed -e 's/\/$//')
 timestamp_now=$(get_timestamp_now)
 if (( ${CRON} == 0 )); then
    echo -n "${timestamp_now} :: ${loadavg} :: Tracing via CLI ${TRACEIP}: "
	# DStrickler Jan 7, 2013: Added full path for Traceroute
	# TODO: Sniff the path there and use it instead of hardcoding it.
	# echo "${TRACEROUTE_PATH} ${TRACE} ${TRACEIP}"
    ${TRACEROUTE_PATH} ${TRACE} ${TRACEIP} > ${OUTDIR}/${timestamp}.${KEY} 2>${IWMTMPDIR}/${timestamp}.errors.log
    RETVAL=$?
    check_exitcode "Tracing ${TRACEIP}"

	CURLURL="${IWMPROTO}://${IWMHOST}/api/put_traces"
	echo -n "${timestamp_now} :: ${loadavg} :: Uploading via CLI to ${CURLURL} "
	OUTPUTTEXT=`cat ${OUTDIR}/${timestamp}.${KEY}`
	curl -s --url "${CURLURL}"  -d key="${KEY}" -d version="${VERSION}" -d payload="${OUTPUTTEXT}"
    echo "OK"
 else
   # DStrickler Jan 7, 2013: Added full path for Traceroute.
   # This is what is executed when run from crontab.
   # TODO: Sniff the path there and use it instead of hardcoding it.
   # TODO: Make this a bash file itself that spans and uploads all by itself so the uplaods don't happen all at once.
   timestamp="$(date +%s)"
   echo "${timestamp_now} :: ${loadavg} :: Tracing via cron to ${TRACEIP}"
   # echo "${TRACEROUTE_PATH} ${TRACE} ${TRACEIP}"
   ${TRACEROUTE_PATH} ${TRACE} ${TRACEIP} > ${OUTDIR}/${timestamp}.${KEY} 2>${IWMTMPDIR}/${timestamp}.errors.log &
 fi

done
wait
stoptwo=$(get_unixtime)

# Take a sample of load average after all the traces are done and upload it below.
# Don't take a sample each time we do a trace as this will just beat on the API
# and not get us any reasonable data.
echo ${loadavg} > ${OUTDIR}/load_average_${timestamp}.${KEY}

# Take each output file and upload it via the API
for file in ${OUTDIR}/*
do
    timestamp_now=$(get_timestamp_now)
    if (( ${CRON} == 0 )); then
        # TODO: Find out what this if/then is for
        if [[ -z ${UPLOADLIST} ]]; then
            UPLOADLIST="${file}"
        else
            UPLOADLIST="${UPLOADLIST},${file}"
        fi
    else
        # Upload each file via the API
        CURLURL="${IWMPROTO}://${IWMHOST}/api/put_traces"
        OUTPUTTEXT=`cat ${file}`
        echo "${timestamp_now} :: ${loadavg} :: Uploading via cron to ${CURLURL}"
        curl -s --url "${CURLURL}" -d key="${KEY}" -d version="${VERSION}" -d payload="${OUTPUTTEXT}"
    fi
done
wait

end=$(get_unixtime)
message="${timestamp_now} :: ${loadavg} :: Test took $(bc <<< ${end}-${start}) seconds (download: $(bc <<< ${stopone}-${start}), trace: $(bc <<< ${stoptwo}-${stopone}), upload: $(bc <<< ${end}-${stoptwo}))"
if (( ${CRON} == 0 )); then
 echo "${message}"
else
 (( ${REPORT} == 1 )) && logger ${LOGGER} "${message}"
fi

# Unlock the lock file by removing it (if it exists).
if [ -e "${LOCKFILE}" ]; then
    rm ${LOCKFILE}
fi
