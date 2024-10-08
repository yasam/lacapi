# lacapi
Latest Cloud API
1. Print help
./lacapi -h

2. You need to prepare a config file(i.e. config.json) to pass config URL, Domain, client id and private key parameters.

3. Calling a basic API(-a)
./lacapi.py -c config.json -a /api/batches?limit=1

4. Calling a pre-defined API for a device
./lacapi.py -c config.json -d JT4D225CB --direct-topology

5. Calling multiple APIs for a device
./lacapi.py -c config.json -d JT4D225CB --direct-topology --direct-stations --direct-hosts

6. Calling pre-defined APIs for a device list from file which has a device identifier on each line
./lacapi.py -c config.json -l devices.txt --direct-topology --direct-stations --direct-hosts

7. Saving output to a folder(-o)
./lacapi.py -c config.json -l devices.txt --direct-topology --direct-stations --direct-hosts -o out

8. Processing each API call's output with a command(file or stdin) (-e)
./lacapi.py -c config.json -l devices.txt --direct-topology --direct-stations --direct-hosts  -e 'jq .'

9. Adding a prefix to output files (-p)
./lacapi.py -c config.json -l devices.txt --direct-topology --direct-stations --direct-hosts  -o out -p mem-leak-

10. Enabling more logs (-v)
./lacapi.py -c config.json -l devices.txt --direct-topology --direct-stations --direct-hosts  -o out -v 10

11. Enabling more info in the log messages(-i)
./lacapi.py -c config.json -l devices.txt --direct-topology --direct-stations --direct-hosts  -o out -v 10 -i

12. Calling APIs in parallel(-m)
./lacapi.py -c config.json -l devices.txt --direct-topology --direct-stations --direct-hosts  -o out -m 4

13. Passing stolen token instead of client id and password from config file(config.json)
TOKEN=absafadsgdsggdsag.....
./lacapi.py -c config.json -t $TOKEN -l devices.txt --direct-topology

14. Passing a specific batch Id, otherwise it will get the latest batch via API(-b).
./lacapi.py -c config.json -d JT4D225CB --batches-topology  -b 1728410400000

