# checkip ![Main](https://github.com/t-a-y-l-o-r/checkip/workflows/Main/badge.svg) ![Dev](https://github.com/t-a-y-l-o-r/checkip/workflows/Dev/badge.svg)
A simple cli wrapper for a variety of security API tools.
Primarily used to detect relations of ip addresses.
Will attempt to resolve their known level of hostility per community standards.

## Flags and Usage
  _-ip_ {ipv4address} -- the flag to use when scanning a single ipv4address. Required if `-if` is not used.

  _-if_ {filepath} --input-file -- the flag to use when scanning multiple
                                      ipv4addresses. Required if `-ip` is not used

  _-u_ {url} --host -- any valid url to resolve as an ip address

  _-f_ --force -- ensures all given ips are scanned,
			even when a record exists

  _-s_ --silent -- runs without sending anything to standardIO

  _-v_ --verbose -- runs with extra output

  _-h_ --help -- displays a list of all flags and basic usage

## Configuration
OTX and VirusTotal api keys must be used for this program to run.
Obtain these from their offical sites for personal use.

NOTE: Please be mindful and respectful of their TOS.

The keys can be provided through the configuration engine in one of the following ways:
(Order of priority)
1. Environ keys: `VIRUS_TOTAL_KEY` and `OTX_KEY` respectively
2. `~/.checkip/config.ini`
3. `./config.ini` where `./` is the active directory for the program

If the `config.ini` setup is used, the following headers and keys are required:

```
[VIRUS_TOTAL]
key=abc123

[OTX]
key=321cba
```

## Up and Coming
  * QOL:
    * output report file
    * ivp6 addresses
  * Features:
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

### Macos
Checkout the current fix in [dev](https://github.com/t-a-y-l-o-r/checkip/tree/dev) and this [issue](https://github.com/t-a-y-l-o-r/checkip/issues/31)

If you are having issues installing `multidict` through pip or pipenv you may need to [reinstall xcode](https://stackoverflow.com/questions/34617452/how-to-update-xcode-from-command-line)
