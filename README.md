# webscanner
A simple ruby script to scan 3rd party web application

[![forthebadge](https://forthebadge.com/images/badges/made-with-ruby.svg)](https://forthebadge.com)


# Installation
```
git clone https://github.com/krishpranav/webscanner
cd webscanner
```

# Setup
```
- bundle install --path vendor
- bundler exec ./webscanner.rb -f [myfile]
```

# Usage
```
-r :: If you want webscanner to perform port scan, use this switch to provide an IP address or IP range

-l :: If you want webscanner to perform port scan, use this switch to provide an input file with new-line separated IP addresses, similar to nmap's -iL option

-s :: Provide custom signature file. [./webscanner.rb -s mysignatures.yaml -f nmap.xml] [Default - signatures.yaml]

-f :: If you do not want webscanner to perform port scan and already have an nmap output in xml format, use this switch to feed the nmap output

-u :: Takes a newline-separated file of URLs saved from previous run of webscanner. See below for more details.

-n :: Tells webscanner to not ping the host while performing the port scan. Standard nmap option.

-p :: Use this switch to provide port number(s)/range

-A :: Use this switch to scan all the 65535 ports. Standard nmap option.

-b [all/form/basic] :: If the discovered application implements authentication, use this switch to brute-force the auth. "all" will brute-force both form & http basic auth. "form" will only brute-force form-based auth. "basic" will only brute-force http basic auth.

-t :: Specify maximum number of threads

-h :: help
```
