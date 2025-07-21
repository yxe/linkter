#!/bin/bash
#
# Linkter: a link linter
# Author: hi@ilia.im
# Version: 1.0
# Updated: July 20, 2025

#### Script setup
################################################################################

CONF_FILE="linkter.conf"
RUN_FILE="linkter-run"
resume_run=false

# Load config
if [ ! -f "$CONF_FILE" ]; then
    echo "Error: configuration file not found!"
    echo "Please ensure '$CONF_FILE' exists in the same directory as the script."
    exit 1
fi

# Source the config file to load variables and arrays
source "./$CONF_FILE"
echo "Configuration loaded from $CONF_FILE."

# Detect system type for compatibility in date commands
if [[ "$(uname)" == "Darwin" ]]; then
    SYSTEM="MACOS"
else
    SYSTEM="LINUX"
fi

#### Helper functions
################################################################################

# Ask the user a yes/no question with a default
# Usage: prompt_user "question" "y"
# The second argument is the default choice ('y' or 'n')
prompt_user() {
    local prompt_text=$1
    local default_choice=$2
    choice=""

    local prompt_str
    if [[ "$default_choice" == "y" ]]; then
        prompt_str="[Y/n]"
    else
        prompt_str="[y/N]"
    fi

    while true; do
        read -p "$prompt_text $prompt_str " -r choice

        # Use default if user presses enter
        if [[ -z "$choice" ]]; then
            choice="$default_choice"
        fi

        # Check for valid input
        case $choice in
            [Yy]* ) choice="y"; break;;
            [Nn]* ) choice="n"; break;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

# Convert http date string to a unix timestamp
http_date_to_timestamp() {
    local date_str
    date_str=$(echo "$1" | tr -d '\r\n')

    if [[ "$SYSTEM" == "MACOS" ]]; then
        date -j -f "%a, %d %b %Y %T %Z" "$date_str" +%s 2>/dev/null
    else
        date -d "$date_str" +%s 2>/dev/null
    fi
}

# Get a file's modification time as a unix timestamp
get_file_timestamp() {
    if [[ "$SYSTEM" == "MACOS" ]]; then
        stat -f %m "$1" 2>/dev/null
    else
        stat -c %Y "$1" 2>/dev/null
    fi
}

# Check if a given content-type string represents a binary file
is_binary_content_type() {
    local content_type="$1"

    # Clean up content type string
    local main_type=$(echo "$content_type" | awk -F';' '{print $1}' | tr -d '[:space:]')

    # If the content type starts with 'text/', it's not binary
    if [[ "$main_type" =~ ^text/ ]]; then
        return 1
    fi

    # Add other known text-based application types to a whitelist
    case "$main_type" in
        application/json|application/xml|application/xhtml+xml|application/javascript)
            return 1
            ;;
    esac

    # If a content type is provided but is not on our whitelist, assume it's binary
    if [[ -n "$main_type" ]]; then
        return 0
    fi

    # If no content type is provided, assume it's not binary to avoid skipping valid files
    return 1
}

#### Script phases
################################################################################

# Download files from a list of urls
download_phase() {
    if [ "$resume_run" = true ]; then
        echo -e "\n${COLOR_PURPLE}Resuming run, skipping download.${COLOR_NC}"
        return
    fi

    echo -e "\n${COLOR_BLUE}--- Starting download ---${COLOR_NC}"

    # Create downloaded directory if it doesn't exist
    mkdir -p "$final_download_dir"

    # Clear or create the link issues file
    > "$download_issues"

    # Get total number of urls for progress indicator
    local total_urls
    total_urls=$(grep -c . "$input_file")
    local current_url_num=0

    # Process each url in the input file
    while IFS= read -r url || [ -n "$url" ]; do
        [ -z "$url" ] && continue # skip empty lines
        ((current_url_num++))

        # Generate a safe filename from the url
        local no_proto=${url#*://}
        local filename=${no_proto//\//_}
        local filepath="$final_download_dir/$filename"

        echo -e "${COLOR_BLUE}[$current_url_num/$total_urls] Checking URL: $url...${COLOR_NC}"

        # Skip if file exists and config is set to not re-download
        if [ "$download_existing" -eq 0 ] && [ -f "$filepath" ]; then
            echo -e "${COLOR_PURPLE}File $filename already exists and download_existing is 0, skipping.${COLOR_NC}"
            continue
        fi

        # Prepare headers for a conditional get request if the file exists locally
        local header_args=()
        if [ -f "$filepath" ]; then
            if [[ "$SYSTEM" == "MACOS" ]]; then
                last_modified=$(date -r "$(get_file_timestamp "$filepath")" +"%a, %d %b %Y %H:%M:%S GMT")
            else
                last_modified=$(date -u -r "$(get_file_timestamp "$filepath")" +"%a, %d %b %Y %H:%M:%S GMT")
            fi
            header_args=("-H" "If-Modified-Since: $last_modified")
        fi

        # Make a head request first to check headers before downloading the body
        local response_headers
        response_headers=$(mktemp)
        local http_code
        http_code=$(curl --connect-timeout 10 -s -L -D "$response_headers" -w "%{http_code}" -o /dev/null "${header_args[@]}" "$url")

        # Check for 304 not modified
        if [ "$http_code" -eq 304 ]; then
            echo -e "${COLOR_CYAN}File $filename not modified since last download, skipping.${COLOR_NC}"
            rm "$response_headers"
            continue
        fi

        # Check if the content is a binary file and skip if it is
        local content_type
        content_type=$(grep -i '^Content-Type:' "$response_headers" | head -1 | awk '{print $2}' | tr -d '\r')
        if is_binary_content_type "$content_type"; then
            echo -e "${COLOR_CYAN}Skipping binary file ($content_type): $url${COLOR_NC}"
            echo "$url" >> "$download_issues"
            echo -e "\tSkipped due to binary Content-Type: $content_type" >> "$download_issues"

            rm "$response_headers"
            continue
        fi

        # Check for success codes (2xx) before downloading the body
        if [[ "$http_code" =~ ^2[0-9]{2}$ ]]; then
            # First, download to a temporary file to check for duplicate content
            local temp_content_file
            temp_content_file=$(mktemp)

            if curl -s -L -o "$temp_content_file" "$url"; then
                local is_duplicate=false
                local matched_file=""

                # Iterate through already downloaded files
                for existing_file in "$final_download_dir"/*; do
                    [ -f "$existing_file" ] || continue

                    if cmp -s "$temp_content_file" "$existing_file"; then
                        is_duplicate=true
                        matched_file=$(basename "$existing_file")
                        break
                    fi
                done

                # Log the issue and skip the download
                if [ "$is_duplicate" = true ]; then

                    echo -e "${COLOR_CYAN}Content of $url is identical to existing file '$matched_file'. Skipping download.${COLOR_NC}"
                    echo "$url" >> "$download_issues"
                    echo -e "\tSkipped (line $current_url_num): content is identical to existing file '$matched_file'." >> "$download_issues"
                    rm "$temp_content_file"
                    continue
                fi

                # If not a duplicate, move the temp file to its final destination
                echo "Downloading to $filepath..."
                mv "$temp_content_file" "$filepath"

                # Get the last-modified header from the server
                local last_modified_header
                last_modified_header=$(grep -i '^Last-Modified:' "$response_headers" | cut -d' ' -f2- | tr -d '\r')

                # If header exists, update file timestamp to match
                if [ -n "$last_modified_header" ]; then
                    local header_timestamp
                    header_timestamp=$(http_date_to_timestamp "$last_modified_header")

                    if [ -n "$header_timestamp" ]; then
                        if [[ "$SYSTEM" == "MACOS" ]]; then
                            touch -t "$(date -r "$header_timestamp" +"%Y%m%d%H%M.%S")" "$filepath" 2>/dev/null
                        else
                            touch -d "@$header_timestamp" "$filepath" 2>/dev/null
                        fi
                    fi
                fi
                echo -e "${COLOR_GREEN}Successfully downloaded $filename.${COLOR_NC}"

            else
                # curl failed
                rm "$temp_content_file"
                echo -e "${COLOR_YELLOW}Failed to download $url.${COLOR_NC}" >&2
                echo "$url" >> "$download_issues"
                echo -e "\t$http_code download failed" >> "$download_issues"
            fi
        # Not a success code, log to issues file
        else
            echo -e "${COLOR_YELLOW}Encountered HTTP $http_code for $url - logged to $download_issues.${COLOR_NC}"
            echo "$url" >> "$download_issues"

            local new_location
            new_location=$(grep -i "location:" "$response_headers" | awk '{print $2}' | tr -d '\r')
            echo -e "\t$http_code error. Location: $new_location" >> "$download_issues"
        fi

        rm "$response_headers"
    done < "$input_file"
    echo -e "${COLOR_GREEN}Download complete.${COLOR_NC}"
}

# Update a key-value pair in the run file
update_run_value() {
    local key=$1
    local value=$2
    local temp_file="$RUN_FILE.tmp"

    # Check if key exists and update it, otherwise add it
    if grep -q "^$key=" "$RUN_FILE"; then
        sed "s/^$key=.*/$key=$value/" "$RUN_FILE" > "$temp_file" && mv "$temp_file" "$RUN_FILE"
    else
        echo "$key=$value" >> "$RUN_FILE"
    fi
}

# Increment a counter for a specific issue type in the run file
increment_issue_count() {
    local type=$1
    local key="count_$type"

    # Grep for the key in the run file
    local current_count
    current_count=$(grep "^$key=" "$RUN_FILE" | cut -d'=' -f2)

    # Key doesn't exist, add it with a count of 1
    if [[ -z "$current_count" ]]; then
        echo "$key=1" >> "$RUN_FILE"
    # Key exists, increment the value
    else
        local new_count=$((current_count + 1))
        update_run_value "$key" "$new_count"
    fi
}

# Check all links in the downloaded files
checking_phase() {
    echo -e "\n${COLOR_BLUE}--- Starting link checks ---${COLOR_NC}"

    # If resuming from a previous session, load the state from the run file
    if [ "$resume_run" = true ]; then
        echo -e "${COLOR_PURPLE}Resuming previous scan. Loading state from $RUN_FILE...${COLOR_NC}"
        source "./$RUN_FILE"
    # If this is the very first check in a new run create the run file and the initial report header
    elif [ ! -f "$RUN_FILE" ]; then
        > "$RUN_FILE"
        update_run_value "report_filename" "$(basename "$final_link_report")"
        update_run_value "pages_with_issues_count" 0
        update_run_value "total_issues_count" 0

        start_time=$(date +"%Y-%m-%d at %H:%M")
        {
            echo "# Linkter link issues report"
            echo "# Scan started on $start_time"
        } > "$final_link_report"
    # Otherwise, the run file exists from a previous step in this same execution (a recursive call),
    # so we just need to load the current counts to continue adding to them
    else
        source "./$RUN_FILE"
    fi

    # Initialize file tracking
    touch "$passed_links"
    touch "$files_checked"

    # Get total number of files to process
    local total_files=0
    for file in "$final_download_dir"/*; do
        [ -f "$file" ] && ((total_files++))
    done

    local already_checked
    already_checked=$(wc -l < "$files_checked" | tr -d ' ')
    local current_file_num=$already_checked

    # Process each file in the directory
    for file in "$final_download_dir"/*; do
        [ -f "$file" ] || continue

        # Skip if file has already been checked (if resuming)
        if grep -Fxq "$file" "$files_checked"; then
            echo -e "\n${COLOR_PURPLE}Skipping already checked file: $file.${COLOR_NC}"
            continue
        fi

        ((current_file_num++))
        echo -e "\n${COLOR_BLUE}[$current_file_num/$total_files] Processing file: $file...${COLOR_NC}"

        local canonical_url
        canonical_url=$(grep -i '<link' "$file" | grep -i 'rel="canonical"' | grep -o 'href="[^"]*"' | cut -d'"' -f2 | head -1)

        if [[ -z "$canonical_url" || ! "$canonical_url" =~ ^https?:// ]]; then
            local filename
            filename=$(basename "$file")
            canonical_url="https://${filename//_//}"
        fi

        local base_url
        base_url=$(echo "$canonical_url" | awk -F/ '{print $1 "//" $3}')

        # Initialize issue tracking for this file
        declare -a file_issues=()

        # Find all anchor tags with their line numbers
        while IFS=: read -r line_num anchor; do
            local message=""
            local issue_type=""

            # Check for empty links
            if [ "$skip_empty_check" -eq 0 ] && [[ "$anchor" =~ ^\<a[[:space:]][^\>]*\>([[:space:]]*|(\&nbsp\;)*[[:space:]]*)\<\/a\>$ ]]; then
                # If configured, ignore empty anchors that have no href attribute
                if [ "$skip_empty_without_href" -eq 1 ] && [[ ! "$anchor" =~ href= ]]; then
                    continue
                fi

                message="- Empty link: $anchor (line $line_num)"
                issue_type="empty"

                echo -e "${COLOR_YELLOW}${message}${COLOR_NC}"
                file_issues+=("\t$message")
                ((total_issues_count++))
                increment_issue_count "$issue_type"
                continue # No href to check, so skip to the next anchor
            fi

            # Extract href and check for various conditions
            local href
            href=$(echo "$anchor" | grep -o '\shref="[^"]*"' | cut -d'"' -f2)

            # Skip if no href or special types
            if [[ -z "$href" || "$href" =~ ^# || "$href" =~ ^mailto: || "$href" =~ ^tel: || "$href" =~ ^fax: || "$href" =~ ^javascript: || "$href" =~ ^sms: || "$href" =~ ^ftp: ]]; then
                continue
            fi

            # Skip if href appears to be part of a js string concatenation
            if [[ "$href" =~ [[:space:]]\+[[:space:]] ]]; then
                echo -e "${COLOR_CYAN}Skipping probable JavaScript in href: $href (line $line_num)${COLOR_NC}"
                continue
            fi

            local original_href="$href"

            # Check for whitespace in url
            if [[ "$href" =~ [[:space:]] ]]; then
                if [ "$skip_whitespace_check" -eq 0 ]; then
                    message="- Whitespace in link: $original_href (line $line_num)"
                    issue_type="whitespace"
                    echo -e "${COLOR_YELLOW}${message}${COLOR_NC}"
                    file_issues+=("\t$message")
                    ((total_issues_count++))
                    increment_issue_count "$issue_type"
                fi
                href="${href// /%20}"
            fi

            # Check for http
            if [[ "$href" =~ ^http:// ]]; then
                if [ "$skip_https_check" -eq 0 ]; then
                    message="- Non-HTTPS link: $original_href (line $line_num)"
                    issue_type="https"
                    echo -e "${COLOR_YELLOW}${message}${COLOR_NC}"
                    file_issues+=("\t$message")
                    ((total_issues_count++))
                    increment_issue_count "$issue_type"
                fi
                href=$(echo "$href" | sed 's|^http://|https://|')
            fi

            # Build full url from potentially modified href
            local full_url

            if [[ "$href" =~ ^/ ]]; then
                full_url="${base_url}${href}"
            elif [[ "$href" =~ ^\.\.?/ ]]; then
                full_url="${canonical_url%/*}/${href}"
            elif [[ ! "$href" =~ ^https?:// ]]; then
                if [[ "$canonical_url" =~ /$ ]]; then
                    full_url="${canonical_url}${href}"
                else
                    full_url="${canonical_url%/*}/${href}"
                fi
            else
                full_url="$href"
            fi

            full_url=$(echo "$full_url" | sed 's|/\./|/|g; s|/[^/]*/\.\./|/|g; s|//$|/|')

            if grep -Fxq "$full_url" "$passed_links"; then
                echo -e "${COLOR_CYAN}Previously verified OK: $full_url (line $line_num).${COLOR_NC}"
                continue
            fi

            # Check http status
            local response_file
            response_file=$(mktemp)
            curl -v -sI -L --connect-timeout 10 -o /dev/null "$full_url" > "$response_file" 2>&1

            local response
            response=$(cat "$response_file")
            rm "$response_file"

            local status_line
            status_line=$(echo "$response" | grep -E "^< HTTP/" | head -1)

            if [ -z "$status_line" ]; then
                message="- Connection failed: $full_url (line $line_num)"
                issue_type="connection_failed"
                echo -e "${COLOR_YELLOW}${message}${COLOR_NC}"
                file_issues+=("\t$message")
                ((total_issues_count++))
                increment_issue_count "$issue_type"
                continue
            fi

            local status_code
            status_code=$(echo "$status_line" | awk '{print $3}')
            local status_message
            status_message=$(echo "$status_line" | cut -d' ' -f4- | tr -d '\n\r')

            if [[ "$status_code" == "200" ]]; then
                echo "$full_url" >> "$passed_links"
                echo -e "${COLOR_GREEN}$status_code $status_message: $full_url (line $line_num)${COLOR_NC}"
                continue
            fi

            # Handle non-200 status codes
            local should_ignore=0
            if [[ "$status_code" == "404" && ${#ignore_404_prefixes[@]} -gt 0 ]]; then
                for prefix in "${ignore_404_prefixes[@]}"; do
                    if [[ "$full_url" == "$prefix"* ]]; then
                        should_ignore=1
                        break
                    fi
                done
            elif [[ "$status_code" == "403" && ${#ignore_403_prefixes[@]} -gt 0 ]]; then
                for prefix in "${ignore_403_prefixes[@]}"; do
                    if [[ "$full_url" == "$prefix"* ]]; then
                        should_ignore=1
                        break
                    fi
                done
            elif [[ "$status_code" == "301" && ${#ignore_301_prefixes[@]} -gt 0 ]]; then
                for prefix in "${ignore_301_prefixes[@]}"; do
                    if [[ "$full_url" == "$prefix"* ]]; then
                        should_ignore=1
                        break
                    fi
                done
            fi

            if [ "$should_ignore" -eq 1 ]; then
                echo "$full_url" >> "$passed_links"
                echo -e "${COLOR_GREEN}Ignoring $status_code from whitelisted prefix: $full_url (line $line_num).${COLOR_NC}"
                continue
            fi

            local is_reportable=false

            if [ ${#check_status_codes[@]} -eq 0 ]; then
                is_reportable=true
            else
                for code_to_check in "${check_status_codes[@]}"; do
                    if [[ "$status_code" == "$code_to_check" ]]; then
                        is_reportable=true
                        break
                    fi
                done
            fi

            if [ "$is_reportable" = true ]; then
                local location
                location=$(echo "$response" | grep -i "^< location:" | tail -1 | awk '{print $3}' | tr -d '\r')

                if [[ -n "$location" ]]; then
                    message="- $status_code $status_message: $full_url -> $location (line $line_num)"
                else
                    message="- $status_code $status_message: $full_url (line $line_num)"
                fi
                issue_type="$status_code"

                echo -e "${COLOR_YELLOW}${message}${COLOR_NC}"
                file_issues+=("\t$message")
                ((total_issues_count++))
                increment_issue_count "$issue_type"
            else
                echo "$full_url" >> "$passed_links"
                echo -e "${COLOR_GREEN}$status_code $status_message: $full_url (line $line_num).${COLOR_NC}"
            fi
        done < <(pcregrep -Mino '<a\s[^>]*>(?s:.*?)</a>' "$file")

        # Output all issues for this file together and update the run state
        if [ ${#file_issues[@]} -gt 0 ]; then
            ((pages_with_issues_count++))

            local issue_count="${#file_issues[@]}"
            local issue_word="issues"
            if [ "$issue_count" -eq 1 ]; then
                issue_word="issue"
            fi

            local issue_header
            issue_header=$(printf "%-3s\tFound %d link %s on: %s" "$pages_with_issues_count." "$issue_count" "$issue_word" "$canonical_url")

            echo -e "${COLOR_YELLOW}$issue_header${COLOR_NC}"

            # Write issues to the report file
            {
                echo "" 
                echo "$issue_header"
                printf '%s\n' "${file_issues[@]}"
            } >> "$final_link_report"

            # Update the run file with the latest counts
            update_run_value "total_issues_count" "$total_issues_count"
            update_run_value "pages_with_issues_count" "$pages_with_issues_count"
        fi

        # Mark file as checked
        echo "$file" >> "$files_checked"
        echo -e "${COLOR_GREEN}Completed processing file: $file.${COLOR_NC}"
    done
}

# Finalize the report with a summary header
finalize_report() {
    echo -e "\n\033[1;34m--- Finalizing report ---\033[0m"

    if [ ! -f "$RUN_FILE" ]; then
        echo "Warning: could not find run file. Cannot generate final report header."
        return
    fi

    # Source the file to get final counts
    source "./$RUN_FILE"

    local start_time
    start_time=$(head -n 2 "$final_link_report" | tail -n 1 | cut -d' ' -f4-)
    local end_time
    end_time=$(date +"%Y-%m-%d at %H:%M")

    local summary
    summary+="# Linkter link issues report\n"
    summary+="# Scan started on $start_time\n"
    summary+="# Found $total_issues_count total link issues on $pages_with_issues_count pages:\n"

    # Read the individual counts from the run file
    while IFS='=' read -r key value; do
        if [[ $key == count_* ]]; then
            local label=${key#count_} # Remove 'count_' prefix

            if [[ "$label" == "empty" ]]; then
                label="Empty links"
            elif [[ "$label" == "whitespace" ]]; then
                label="Whitespace links"
            elif [[ "$label" == "https" ]]; then
                label="Non-HTTPS links"
            elif [[ "$label" == "connection_failed" ]]; then
                label="Connection failures"
            fi

            summary+="### $label: $value\n"
        fi
    done < "$RUN_FILE"

    summary+="# Scan finished on $end_time\n"
    summary+=$(printf '#%.0s' {1..80})

    local report_body
    report_body=$(tail -n +3 "$final_link_report" | sed '1d')

    {
        echo -e "$summary"
        echo ""
        echo -e "$report_body"
    } > "$final_link_report"

    rm "$RUN_FILE"

    echo -e "\n\033[1;32mProcessing complete. Report saved to $final_link_report.\033[0m"
}

# Recursively check passed links if the flag is enabled
recursive_check_phase() {
    echo -e "\n${COLOR_BLUE}--- Starting recursive check of passed links ---${COLOR_NC}"

    # Extract base urls from the original input file
    declare -a base_urls_to_check=()
    echo "Extracting base URLs from $initial_input_file..."

    # Handle files with no trailing newline
    while IFS= read -r url || [[ -n "$url" ]]; do
        [ -z "$url" ] && continue

        local base_url
        base_url=$(echo "$url" | awk -F/ '{print $1 "//" $3}')

        # Add to array if not already there
        if [[ ! " ${base_urls_to_check[@]} " =~ " ${base_url} " ]]; then
            base_urls_to_check+=("$base_url")
        fi
    done < "$initial_input_file"

    echo -e "${COLOR_CYAN}Will recursively check links matching: ${base_urls_to_check[*]}${COLOR_NC}"

    # Track all links queued for checking to prevent duplicates and re-checking
    local all_queued_links="$work_dir/all-queued-links.txt"
    cat "$initial_input_file" > "$all_queued_links"

    local iteration=1
    while true; do
        echo -e "\n${COLOR_PURPLE}Recursive check, iteration $iteration...${COLOR_NC}"
        
        # File to hold the next batch of urls to check
        local next_input_file="$work_dir/next-links-to-check.txt"
        > "$next_input_file"

        local new_links_found=0

        if [ ! -f "$passed_links" ]; then
            echo -e "${COLOR_YELLOW}'$passed_links' not found. Nothing to check.${COLOR_NC}"
            break
        fi
        
        # Read the list of currently passed links
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            
            # Skip if we've already queued this url for checking
            if grep -Fxq "$url" "$all_queued_links"; then
                continue
            fi
            
            # Check if the url's base matches our target base urls
            local url_base
            url_base=$(echo "$url" | awk -F/ '{print $1 "//" $3}')
            
            local match=false

            for base in "${base_urls_to_check[@]}"; do
                if [[ "$url_base" == "$base" ]]; then
                    match=true
                    break
                fi
            done
            
            if [ "$match" = true ]; then
                echo -e "${COLOR_GREEN}Found new matching link to check: $url${COLOR_NC}"
                echo "$url" >> "$next_input_file"
                echo "$url" >> "$all_queued_links" # Add to tracker to prevent re-queuing
                ((new_links_found++))
            fi
        done < "$passed_links"

        if [ "$new_links_found" -eq 0 ]; then
            echo -e "${COLOR_GREEN}No new links matching base URLs were found in '$passed_links'. Recursive check complete.${COLOR_NC}"
            break
        else
            echo -e "${COLOR_CYAN}Found $new_links_found new links to process in this iteration.${COLOR_NC}"
            
            # Update the global input_file variable for the next run of the phases
            input_file="$next_input_file"
            
            # Re-run the core phases with the new list of links
            download_phase
            checking_phase
            
            ((iteration++))
        fi
    done
    # Clean up intermediate files
    rm "$all_queued_links" "$work_dir/next-links-to-check.txt" 2>/dev/null
}

#### Main execution
################################################################################

main() {
    local check_passed_flag=false
    local positional_args=()
    local temp_url_file="" # Path to a temporary file if needed

    # Parse arguments for flags and positional args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check-passed)
                check_passed_flag=true
                shift
                ;;
            *)
                positional_args+=("$1")
                shift
                ;;
        esac
    done

    # Restore positional arguments
    set -- "${positional_args[@]}"

    if [ $# -eq 0 ]; then
        echo "Error: no URL list file or starting URL provided."
        echo "Usage: $0 <url-list-file | starting-url> [optional-prefix] [--check-passed]"
        exit 1
    fi

    # Check if the first argument is a url or a file path
    # If url, enable recursive check automatically
    if [[ "$1" =~ ^https?:// ]]; then
        echo -e "${COLOR_CYAN}Starting URL detected. Enabling recursive check automatically.${COLOR_NC}"
        check_passed_flag=true
        
        # Create a temporary file to hold the single url, which will act as our input file
        temp_url_file=$(mktemp)
        echo "$1" > "$temp_url_file"
        
        # Set globals from arguments
        input_file="$temp_url_file"
        initial_input_file="$temp_url_file"
        prefix="$2"

        # Ensure the temporary file is cleaned up when the script exits
        trap 'rm -f "$temp_url_file"' EXIT
    # Argument is a file path
    else
        input_file="$1"
        initial_input_file="$1" 
        prefix="$2"
    fi
    
    # If a prefix is provided, create a directory for it
    work_dir="."
    if [ -n "$prefix" ]; then
        work_dir="$prefix"
        mkdir -p "$work_dir"

        # Prepend the directory to all output file paths
        RUN_FILE="$work_dir/$RUN_FILE"
        passed_links="$work_dir/$passed_links"
        files_checked="$work_dir/$files_checked"
        download_issues="$work_dir/$download_issues"
    fi

    final_download_dir="$work_dir/${prefix:+$prefix-}$download_directory"
    # Make final_link_report global so checking_phase can access it
    final_link_report=""

    # Handle pre-run checks for resuming or starting fresh
    if [ -f "$RUN_FILE" ]; then
        echo "Incomplete run detected from the presence of '$RUN_FILE'."
        prompt_user "Do you want to continue the previous run?" "y"

        if [[ "$choice" == "y" ]]; then
            resume_run=true
            source "./$RUN_FILE"
            final_link_report="$work_dir/$report_filename"
        else
            rm "$RUN_FILE"
            echo "Removed '$RUN_FILE'. Starting a fresh scan."
        fi
    fi

    if [ "$resume_run" = false ]; then
        local timestamp
        timestamp=$(date +"%Y-%m-%d-%H-%M")

        local report_base_name="${link_report%.txt}"
        final_link_report="$work_dir/${prefix:+$prefix-}${report_base_name}-${timestamp}.txt"

        if [ -d "$final_download_dir" ]; then
            prompt_user "Existing download directory '$final_download_dir' found. Re-download all files?" "n"
            if [[ "$choice" == "y" ]]; then
                rm -rf "$final_download_dir"
            fi
        fi

        if [ -f "$passed_links" ]; then
            prompt_user "Existing passed links file '$passed_links' found. Clear it for a fresh run?" "n"
            if [[ "$choice" == "y" ]]; then
                > "$passed_links"
            fi
        fi

        if [ -f "$files_checked" ]; then
            prompt_user "Existing checked files log '$files_checked' found. Clear it for a fresh run?" "n"
            if [[ "$choice" == "y" ]]; then
                > "$files_checked"
            fi
        fi

        > "$final_link_report"
    fi

    # Run the initial phases of the script
    download_phase
    checking_phase

    # If the flag is set, run the recursive check
    if [ "$check_passed_flag" = true ]; then
        recursive_check_phase
    fi

    # Finalize the report
    finalize_report
}

# Execute main function with all script arguments
main "$@"
