# checkip
A simple cli wrapper for a variety of security API tools.
Primarily used to detect relations of ip addresses.
Will attempt to resolve their known level of hostility per community standards.

## Flags and Usage
  _-ip_ {ipv4address} -- the flag to use when scanning a single ipv4address. Required if `-if` is not used.

  _-if_ {filepath} --input-file -- the flag to use when scanning multiple
                                      ipv4addresses. Required if `-ip` is not used

  _-ap_ --all-ips -- ensures all given ips are scanned,
			even when a record exists (think `--force`)

  _-h_ --help -- displays a list of all flags and basic usage


## Up and Coming
  * QOL:
    * setup an rc/dotfile per the unix convention
      * allow for inital config / auto-detect of existing dot file structure
    * reformat flags to be standardized (i.e. --force, --verbose, etc)
    * ip log file
    * output report file
  * Features:
    * ivp6 addresses
    * URL option?
    * For VirusTotal long report, include:
      * Subdomains
      * Top 20 URLs
      * Communicating Files
      * Files Referring
    * specify which client will be reached out to (have a flag for each?)
    * verbose flag / silent flag
  * Architecture stuff:
    * local storage?

## Known Issues
Mac users, please add this line to your shell's dotfile:
`export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=Yes`
