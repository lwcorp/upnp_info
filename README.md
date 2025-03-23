## Purpose
This script was written so that anyone can easily find devices on their network. While tools like this have and do exist, none are as simple as downloading a file and executing it.

## Dependencies

### Python
This script depends on 'requests'. You can install requests via pip:

``
pip install requests
``

### PowerShell
None

## Usage
The script takes no input and is simply executed
### Optional parameters
``
[-h|--help] [--onlylocation] [--onlyigd]
``
- `-h, --help`: Print help message and usage information
- `--onlylocation`: Only print discovered locations
- `--onlyigd`: Only print IGD (Internet Gateway Device) devices, i.e. UPnP

The optional parameters can filter the results into just what you may need. For example, `--onlylocation --onlyigd` can be quite helpful to pass to other programs just the XML address of your UpnP devices, also known as UPnP Presentation url (with port and XML filename).

### Implementation
#### Python

``
python upnp_info.py [parameters]
``
#### PowerShell

``
powershell -ExecutionPolicy Bypass -File "upnp_info.ps1" [parameters]
``

## Troubleshooting
The script needs to be able access UDP port 1900. If you aren't getting any results but you think you should be then check your firewall.

## Features
The script discovers all UPnP servers within multicast range

```
$ python upnp_info.py 
[+] Discovering UPnP locations
[+] Discovery complete
[+] 11 locations found:
	-> http://192.168.0.254:49152/wps_device.xml
	-> http://192.168.1.217:49153/description.xml
	-> http://192.168.1.217:35848/rootDesc.xml
	-> http://192.168.1.217:32469/DeviceDescription.xml
	-> http://192.168.1.217:49152/tvdevicedesc.xml
	-> http://192.168.1.217:35439/rootDesc.xml
	-> http://192.168.1.251:49451/luaupnp.xml
	-> http://192.168.1.1:45973/rootDesc.xml
	-> http://192.168.1.1:1990/WFADevice.xml
	-> http://192.168.1.1:1901/root.xml
	-> http://192.168.1.217:8200/rootDesc.xml
```
It parses the service's XML and displays it for the user:

```
[+] Loading http://192.168.1.217:49153/description.xml...
	-> Server String: Linux/4.4.0-36-generic, UPnP/1.0, MediaTomb/0.12.2
	==== XML Attributes ===
	-> Device Type: urn:schemas-upnp-org:device:MediaServer:1
	-> Friendly Name: MediaTomb
	-> Manufacturer: (c) 2005-2008 Gena Batyan <bgeradz@mediatomb.cc>, Sergey Bostandzhyan <jin@mediatomb.cc>, Leonhard Wimmer <leo@mediatomb.cc>
	-> Manufacturer URL: http://mediatomb.cc/
	-> Model Description: Free UPnP AV MediaServer, GNU GPL
	-> Model Name: MediaTomb
	-> Model Number: 0.12.2
	-> Services:
		=> Service Type: urn:schemas-upnp-org:service:ConnectionManager:1
		=> Control: /upnp/control/cm
		=> Events: /upnp/event/cm
		=> API: http://192.168.1.217:49153/cm.xml
			- GetCurrentConnectionIDs
			- GetCurrentConnectionInfo
			- GetProtocolInfo
		=> Service Type: urn:schemas-upnp-org:service:ContentDirectory:1
		=> Control: /upnp/control/cds
		=> Events: /upnp/event/cds
		=> API: http://192.168.1.217:49153/cds.xml
			- Browse
			- GetSearchCapabilities
			- GetSortCapabilities
			- GetSystemUpdateID
```
It can browse file shares:

```
[+] Content browsing available. Looking up base directories...
		Storage Folder: PC Directory
		Storage Folder: Photos
		Storage Folder: wat
```

It can show port mappings:

```
[+] IGD port mapping available. Looking up current mappings...
		[UDP] *:60579 => 192.168.1.186:60579 | Desc: None
```
