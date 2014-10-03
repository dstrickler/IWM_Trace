#!/bin/bash
#
# ---------------------------------------------------------------------------
# DStrickler Sep 12, 2014
# Code has been altered to use curl to get/put data via a web-based API
# instead of by FTP, as the FTP servers prooved too hard to load balance
# as IWM grew in size.
#
# This code is based on work by MiikkaK - many thanks.
# Thanks to MicahB & TreyT for beta testing.
#
# This code is available on GitHub at https://github.com/dstrickler/IWM_Trace
## ---------------------------------------------------------------------------
#
# This is your Tracer Key. Make sure this is *unique* for each bash file you run.
# Additional keys can be generated from our portal: www.internetweathermap.com
KEY="replace_with_your_personal_key"
#
# 5-minute "not to exceed" load average threshold.
# If this system is running above this load average, IWM run will be skipped
HIGHLOAD="5"
#
# Report runtime of script into syslog when run from cron, 1=yes
REPORT="1"
#
# TODO: Add a verbose logging switch and a log() function.
# TODO: Make all variables upper case.
# TODO: Improve code section spacing & cleanup comments.


################################
# DO NOT EDIT BEYOND THIS LINE #
################################
VERSION="4.0.029"
IWMHOST="api.internetweathermap.com"
IWMDIR="iwm"
IWMPROTO="http"
LOGGER="-i -p INFO -t iwm"
HOPS="15"
# The traceroute "-I" option is a little faster, but can only be run in super-user mode.
TRACE=" -n -m ${HOPS}"
AUTOUPGRADE=1
CRON=0
OS_KERNEL=$(uname -v 2>/dev/null)
#####################################################################
# DON'T REMOVE THIS COMMENT LINE.                                   #
# THIS CODE IS NEEDED FOR AUTO-UPDADE: 65b8745a568sbd76n0asdiu6vasd #
#####################################################################

get_unixtime() {
    if [[ $OS_KERNEL =~ "Darwin" ]]; then
        # We are on OSX, and the trailing "N" makes trouble for the bc command at the end.
        echo $(date +%s.%3)
    else
        echo $(date +%s.%3N)
    fi
    }

get_timestamp_now() {
    echo $(date +"%m-%d-%Y %H:%M:%S")
}

info() {
 if (( ${CRON} == 1 )); then
 {
   echo "${timestamp_now} :: ${loadavg} :: ${1}"
   type -p logger > /dev/null 2>&1
   if (( ${?} == 0 )); then
     logger ${LOGGER} "${1}"
   fi
   }
 else
   echo "${timestamp_now} :: ${loadavg} :: ${1}"
 fi
}

error() {
 loadavg=$(get_loadavg)
 timestamp_now=$(get_timestamp_now)
 info "[!] Test cancelled: ${1}"
 cleanup
 (( ${2} == 1 )) && exit 1
}

check_exitcode() {
 if (( ${RETVAL} == 0 )); then
   info "${1}: OK"
 else
   info "${1}: FAILED"
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

cleanup() {
    # Cleanup our temp directory and lockfile
    if [ -e "${IWMTMPDIR}" ]; then
        rm -rf ${IWMTMPDIR}
    fi
    if [ -e "${LOCKFILE}" ]; then
        rm -rf ${LOCKFILE}
    fi
}
# These are defined over again inside of any loop to keep them current.
loadavg=$(get_loadavg)
timestamp_now=$(get_timestamp_now)

# Find out if we are being run from the CLI or CRON.
tty -s
(( ${?} == 1 )) && CRON="1"

# Figure out where traceroute lives, and set it as a var for use later.
# While the "type" command should fine it, we search for it in some
# obvious places just in case.
TRACEROUTE_PATH=$(type -p  traceroute)
NICE_PATH=$(type -p nice)
if [ -f "/usr/bin/traceroute" ]; then
    TRACEROUTE_PATH="/usr/bin/traceroute"
fi
if [ -f "/usr/sbin/traceroute" ]; then
    # Configuration for OSX
    TRACEROUTE_PATH="/usr/sbin/traceroute"
fi
if [ -f "/bin/traceroute" ]; then
    TRACEROUTE_PATH="/bin/traceroute"
fi
if [ ! -f "${TRACEROUTE_PATH}" ]; then
    error "Traceroute not found on your system as '${TRACEROUTE_PATH}' - halting" 1
fi

# If we don't have one of these programs, halt, and let the user know.
# The traceroute command can't be found on OSX, so I removed it from the test
# and now it has it's own variable set to its path.
for cmd in awk bc date curl logger mkdir sed tty uptime wc
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

# Make the sub-dir "output" under the the temp directory
mkdir ${IWMTMPDIR}/output

# Find out a existing directory that's writable for the lock file.
# If all else fails, use your home directory.
LOCKFILE="~/iwm.lock"
if [[ -d '/var/lock'  &&  -w '/var/lock' ]]; then
    LOCKFILE="/var/lock/iwm.lock"
fi
if [[ -d '/tmp'  &&  -w '/tmp' ]]; then
    LOCKFILE="/tmp/iwm.lock"
fi

# Run a check to see if there is a new version of the code.
# If so, replace the code we are currently running.
VERSION_FILE="${IWMTMPDIR}/iwm_trace_bash_version.txt"
CURLURL="${IWMPROTO}://${IWMHOST}/api/get_iwm_trace_bash_version"
curl -o ${VERSION_FILE} -s --url "${CURLURL}"
current_version=`cat ${VERSION_FILE}`

# Check that the version we just got looks like a valid version number.
# If not, bail out - something has happened that we don't even want to proceed.
if [[ ${AUTOUPGRADE} == 1 ]]; then
    if [[ "${current_version}" =~ ^[0-9]\.[0-9]\.[0-9][0-9][0-9]$ ]] ; then
        if [[ "${current_version}" == "${VERSION}" ]] ; then
            info "This is the most current version of this software: ${VERSION}"
        else
            path_to_bash="${0}"
            temp_file="${IWMTMPDIR}/new_bash_version.txt"
            info "This verison needs to be upgraded from '${VERSION}' to '${current_version}'."
            info "Saving version ${current_version} to ${temp_file}..."
            CURLURL="${IWMPROTO}://${IWMHOST}/api/get_iwm_trace_bash_code/${KEY}"
            curl -o "${temp_file}" -s --url "${CURLURL}"

            # Now that the new code is in a temp file, see if there is a unique string
            # in the code that signifies that it was downloaded OK. If the file was scrabbled
            # or another error msg came in its place, this code will not be there, and the
            # upgrade will not proceed. This code is defined at the top of the file in
            # a comment.
            temp_file_string=`cat ${temp_file}`
            if [[ $temp_file_string == *65b8745a568sbd76n0asdiu6vasd* ]]; then
                info "Upgrading current code..."
                cp ${temp_file} ${path_to_bash}
                chmod +x ${path_to_bash}
                if [[ -f ${path_to_bash} ]]; then
                    rm ${temp_file}
                fi
                info "Halting current code so it runs the new version the next time it's run."
                exit
            else
                info "There was a problem upgrading the software. Running existing version for now."
                if [[ -f ${path_to_bash} ]]; then
                    rm ${temp_file}
                fi
            fi
        fi
    else
        error "The version pulled from the IWM server is corrupted: '${current_version}' " 1
    fi
fi
 

# If the lock file is too old, delete it.
if [[ -e ${LOCKFILE} ]]; then
    if [ "$(find ${LOCKFILE} -mmin +1)" != "" ]; then
        info "Lockfile ${LOCKFILE} is too old - delete it."
        rm ${LOCKFILE}
    else
        # Don't clean out the lockfile by calling error(). We need the lockfile to stay in place.
        info "Lockfile (${LOCKFILE}) is too fresh to run."
        exit
    fi
fi

# If the lock file exists, we are probobly still running - exit out.
if [[ -e ${LOCKFILE} ]]; then
    error "Previous test still on-going. Recent lock file found at ${LOCKFILE}" 1
fi


# Lock the bash script by creating the lock file.
start=$(get_unixtime)
echo "${start}" > ${LOCKFILE}

# Trap for an O/S to get a better understanding of the environment.
# Would be better if it was a Linux flavor.
server_signature="$(uname -a 2>/dev/null)"

# WORKLIST is the file we are about to download
WORKLIST=${IWMTMPDIR}/worklist.${KEY}

# OUTDIR is where we will place the output of traceroutes, etc.
OUTDIR=${IWMTMPDIR}/output

# (( ${CRON} == 0 )) && echo -n "${timestamp_now} :: ${loadavg} :: Fetching new worklist: "

# If we have an old worklist, clear it out
if [ -e "${WORKLIST}" ]; then
    info "Removing old worklist..."
    rm ${WORKLIST}
fi

# Get a worklist from the API. Easy, quick and reliable.
CURLURL="${IWMPROTO}://${IWMHOST}/api/get_worklist/${KEY}"
curl -o ${WORKLIST} -s --url "${CURLURL}"
RETVAL=$?
stopone=$(get_unixtime)
check_exitcode "Fetching new worklist for key '${KEY}'"
[[ -s ${WORKLIST} ]] || error "Worklist file is empty" 1
NUMOFLINES=$(wc -l < ${WORKLIST} | sed -e 's/^ *//' -e 's/ *$//')
info "Worklist contains ${NUMOFLINES} traces to perform."

for ip in $(cat ${WORKLIST})
do
    loadavg=$(get_loadavg)
    (( $(bc <<< "${loadavg} >= ${HIGHLOAD}") == 1 )) && \
    error "5-minute load average ${loadavg} is TOO HIGH" 1

    # We always need a unique timestamp for a unique filename.
    # If the filename exists, loop and get another filename.
    # This is very importaint code as the bash code runs fast.
    utstamp="$(get_unixtime)"
    while [[ -f ${OUTDIR}/${utstamp}.${KEY} ]]; do
       utstamp="$(get_unixtime)"
    done

    TRACEIP=$(echo ${ip} | sed -e 's/\/$//')
    timestamp_now=$(get_timestamp_now)
    if (( ${CRON} == 0 )); then
        ${TRACEROUTE_PATH} ${TRACE} ${TRACEIP} > ${OUTDIR}/${utstamp}.${KEY} 2>${IWMTMPDIR}/${utstamp}.errors.log
        RETVAL=$?
        check_exitcode "Tracing via CLI to ${TRACEIP}"

        CURLURL="${IWMPROTO}://${IWMHOST}/api/put_traces"
        echo -n "${timestamp_now} :: ${loadavg} :: Uploading via CLI to ${CURLURL} "
        OUTPUTTEXT=`cat ${OUTDIR}/${utstamp}.${KEY}`
        # Added "nice" to help keep CPU loads down as of Sept 25, 2014
        ${NICE_PATH} -n 19 curl -s --url "${CURLURL}"  -d key="${KEY}" -d version="${VERSION}" -d payload="${OUTPUTTEXT}" -d server_signature="${server_signature}"
        echo "OK"
    else
       # This is what is executed when run from crontab.
       # Added "nice" to help keep CPU loads down as of Sept 25, 2014
       info "Tracing via cron to ${TRACEIP}"
       ${NICE_PATH} -n 19 ${TRACEROUTE_PATH} ${TRACE} ${TRACEIP} > ${OUTDIR}/${utstamp}.${KEY} 2>${IWMTMPDIR}/${utstamp}.errors.log &

    fi

    # Keep the lockfile timestamp fresh
    echo "${utstamp}" > ${LOCKFILE}

done
wait
stoptwo=$(get_unixtime)

# Take a sample of load average after all the traces are done and upload it below.
# Don't take a sample each time we do a trace as this will just beat on the API
# and not get us any reasonable data.
# Since this file is only written once, its filename should be unique.
echo ${loadavg} > ${OUTDIR}/load_average_${utstamp}.${KEY}


# If run from cront, take all the payload files from the temp dir and put them
# into a single var called single_payload. Then upload them.
# If run from the CLI, the uploads have already been done - skip this.
if (( ${CRON} == 1 )); then
single_payload=""
for file in ${OUTDIR}/*
    do
        # Append each file's contents to a var so we can do just one upload below.
        OUTPUTTEXT=`cat ${file}`
        single_payload=$(printf "${single_payload} ${OUTPUTTEXT}\n--[LINEBREAK]--\n")

    done

    # Now, in one clean API call, upload the single_payload variable.
    CURLURL="${IWMPROTO}://${IWMHOST}/api/put_single_payload_traces"
    info "Uploading tracer payloads..."
    curl -s --url "${CURLURL}" -d key="${KEY}" -d version="${VERSION}" -d payload="${single_payload}" -d server_signature="${server_signature}"
fi

# Show stats on how long everything took to acomplish.
end=$(get_unixtime)
run_total=$(bc <<< ${end}-${start} | sed -e 's/^ *//' -e 's/ *$//')
run_download=$(bc <<< ${stopone}-${start} | sed -e 's/^ *//' -e 's/ *$//')
run_trace=$(bc <<< ${stoptwo}-${stopone} | sed -e 's/^ *//' -e 's/ *$//')
run_upload=$(bc <<< ${end}-${stoptwo} | sed -e 's/^ *//' -e 's/ *$//')
message="${timestamp_now} :: ${loadavg} :: Test took ${run_total} seconds (download: ${run_download}, trace: ${run_trace}, upload: ${run_upload})"
if (( ${CRON} == 0 )); then
 echo "${message}"
else
 (( ${REPORT} == 1 )) && logger ${LOGGER} "${message}"
 echo "${message}"
fi

# Uploading the stats from the Bash run. Must be done at end of run as a seperate upload.
info "Uploading statistics about this run of the bash file"
CURLURL="${IWMPROTO}://${IWMHOST}/api/put_run_statistics"
info "Uploading bash code run statistics..."
curl -s --url "${CURLURL}" -d key="${KEY}" -d version="${VERSION}" -d run_total="${run_total}" -d run_download="${run_download}" -d run_trace="${run_trace}" -d run_upload="${run_upload}"


# Cleanup any temp variables and log that we are done.
cleanup
info " -----[ IWM bash script completed OK ]-----"
