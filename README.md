# Linkter

A bash script to check a list of files for broken links and other potential link issues.

## Usage

`./linkter.sh <url-list-file | starting-url> [optional-prefix] [--check-passed] [--config <file>]`

* **`<url-list-file | starting-url>`**: The starting point for the scan. This can be either:
    * A plain text file with one URL per line that you want to check.
    * A single starting URL (e.g., `https://example.com`) to begin a recursive crawl.
* **`optional-prefix`**: An optional string to prefix the name of the report file and to name a directory for the output files.
* **`--check-passed`**: An optional flag to enable recursive checking when providing a `url-list-file`. This is enabled automatically when a `starting-url` is provided instead.
* **`--config <file>`**: An optional flag to override the default config file with the specified file.

## Features

* **Comprehensive link checking**: The script can be configured to check for various HTTP status codes like 404 (Not Found) or 301 (Moved Permanently). It can also detect and report other common issues like non-HTTPS links, links containing whitespace, and empty anchor tags.
* **Recursive website crawling**: Start with a single URL and the script can recursively find and check new links on the same domain, allowing for a deep crawl of an entire site.
* **Intelligent downloading**:
    * **Conditional fetching**: Uses `If-Modified-Since` headers to only re-download a page if it has changed on the server since the last scan, saving bandwidth and time.
    * **Duplicate content prevention**: Before saving a file, the script checks if its content is identical to an already downloaded file to avoid storing redundant copies.
    * **Binary file skipping**: Automatically detects and skips non-HTML files (like PDFs, DOCX, etc.) based on their `Content-Type` header.
* **Customizable error handling**: You can create whitelists of URL prefixes to ignore specific errors (e.g., 404, 403, 301) for links that are known to be false-positives.
* **Session resumption**: If a scan is interrupted, it can be resumed from where it left off, preventing the need to start over from scratch.
* **Organized reporting**: Generates a clean, timestamped report file that groups all found issues by the page they appeared on and provides a final summary of all error types.
* **Highly portable**: Runs on almost any Unix-like system with no dependencies besides pcregrep.

## Advanced usage

### Prefix and directory functionality

If you provide a prefix, the script will create a directory named after that prefix (e.g., `./linkter.sh urls.txt my-client` creates a directory named `my-client`).

All generated files for that run—including the report, downloaded web pages, and cache files (`passed-links.txt`, `files-checked.txt`, etc.) will be stored inside this directory. This allows you to run multiple, separate scans without their output files overwriting each other. Additionally, the report filename will be prefixed, as will the downloaded files directory name.

If no prefix is provided, all files will be created in the current directory.

### Recursive checking (`--check-passed`)

The easiest way to perform a deep crawl of a website is to provide a single **`starting-url`** as the first argument. When you do this, the recursive check is enabled automatically. The script will start at the given URL, find all links on that page, check them, and then recursively check any of those links that belong to the same website. Use the `skip_files` array in the config file to specify URLs that should be skipped (e.g. archived content).

You can also enable this feature when using a file of URLs by adding the `--check-passed` flag.

## Limitations

This script will only work with static HTML output as it uses cURL to fetch pages. Dynamic content that is generated via JavaScript will not be fetched.

## Requirements

* bash
* pcregrep