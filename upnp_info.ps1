using namespace System.Net.Sockets
using namespace System.Text
using namespace System.Xml
using namespace System.Collections.Generic

$helpText = @"
UPnP Discovery and Information Script

USAGE:
    $(Split-Path -Leaf $PSCommandPath) [OPTIONS]

OPTIONS:
    -h, --help          Show this help message
    --onlylocation      Only print discovered UPnP locations
    --onlyigd           Only print IGD (Internet Gateway Device) related information

EXAMPLES:
    powershell -ExecutionPolicy Bypass -File $(Split-Path -Leaf $PSCommandPath) --onlylocation
    powershell -ExecutionPolicy Bypass -File $(Split-Path -Leaf $PSCommandPath) --onlyigd
"@

$script:outputData = @{}

function Write-Output-Location {
    param (
        [string]$location,
        [string]$message
    )
    
    if (-not $script:outputData.ContainsKey($location)) {
        $script:outputData[$location] = [List[string]]::new()
    }
    $script:outputData[$location].Add($message)
}

function Discover-PnPLocations {
    $locations = [HashSet[string]]::new()
    $locationRegex = [regex]::new("location:[ ]*(.+)`r`n", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    $ssdpDiscover = "M-SEARCH * HTTP/1.1`r`n" +
                    "HOST: 239.255.255.250:1900`r`n" +
                    "MAN: `"ssdp:discover`"`r`n" +
                    "MX: 1`r`n" +
                    "ST: ssdp:all`r`n" +
                    "`r`n"

    $socket = New-Object System.Net.Sockets.Socket([AddressFamily]::InterNetwork, [SocketType]::Dgram, [ProtocolType]::Udp)
    $socket.SendTimeOut = 3000
    $socket.ReceiveTimeout = 3000
    
    try {
        $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("239.255.255.250"), 1900)
        $bytes = [Encoding]::ASCII.GetBytes($ssdpDiscover)
        $socket.SendTo($bytes, $endpoint) | Out-Null
        
        $receiveBuffer = New-Object byte[] 1024
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        
        while ($timer.ElapsedMilliseconds -lt 3000) {
            try {
                $remoteEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $endPointRef = [ref]$remoteEndpoint
                $received = $socket.ReceiveFrom($receiveBuffer, [ref]$remoteEndpoint)
                $response = [Encoding]::ASCII.GetString($receiveBuffer, 0, $received)
                
                $match = $locationRegex.Match($response)
                if ($match.Success) {
                    $location = $match.Groups[1].Value
                    if (-not $locations.Contains($location)) {
                        $locations.Add($location) | Out-Null
                    }
                }
            }
            catch [System.Net.Sockets.SocketException] {
                break
            }
        }
    }
    finally {
        $socket.Close()
    }
    
    return $locations
}

function Get-PortMappings {
    param (
        [string]$location,
        [string]$controlUrl,
        [string]$serviceType
    )
    
    $index = 0
    while ($true) {
        $payload = @"
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetGenericPortMappingEntry xmlns:u="$serviceType">
<NewPortMappingIndex>$index</NewPortMappingIndex>
</u:GetGenericPortMappingEntry>
</s:Body>
</s:Envelope>
"@
        
        $headers = @{
            'SOAPAction' = "`"$serviceType#GetGenericPortMappingEntry`""
            'Content-Type' = 'text/xml;charset="utf-8"'
        }
        
        try {
            $response = Invoke-WebRequest -Uri $controlUrl -Method Post -Body $payload -Headers $headers
            if ($response.StatusCode -ne 200) { break }
            
            $xmlResponse = [xml]$response.Content
            $externalIP = $xmlResponse.SelectSingleNode("//NewRemoteHost").InnerText
            if (-not $externalIP) { $externalIP = '*' }
            
            $mapping = "`t`t[$($xmlResponse.SelectSingleNode('//NewProtocol').InnerText)] " +
                      "$externalIP`:$($xmlResponse.SelectSingleNode('//NewExternalPort').InnerText) => " +
                      "$($xmlResponse.SelectSingleNode('//NewInternalClient').InnerText):" +
                      "$($xmlResponse.SelectSingleNode('//NewInternalPort').InnerText) | " +
                      "Desc: $($xmlResponse.SelectSingleNode('//NewPortMappingDescription').InnerText)"
            
            Write-Output-Location -location $location -message $mapping
            $index++
        }
        catch {
            break
        }
    }
}

function Parse-UPnPLocations {
    param (
        [HashSet[string]]$locations,
        [switch]$OnlyIGD,
        [switch]$OnlyLocation
    )
    
    foreach ($location in $locations) {
        Write-Output-Location -location $location -message "[+] Loading $location..."
        
        try {
            $response = Invoke-WebRequest -Uri $location -TimeoutSec 5 -UserAgent "UPnP/2.0" -UseBasicParsing
            $server = $response.Headers["Server"]
            
            if ($server) {
                Write-Output-Location -location $location -message "`t-> Server String: $server"
            }
            else {
                Write-Output-Location -location $location -message "`t-> No server string"
            }
            
            Write-Output-Location -location $location -message "`t==== XML Attributes ==="
            
            try {
                $xmlContent = $response.Content
                $xmlContent = $xmlContent.Trim()
                
                # Remove invalid characters
                $xmlContent = [regex]::Replace($xmlContent, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
                
                $xml = New-Object System.Xml.XmlDocument
                $xml.PreserveWhitespace = $true
                $xml.LoadXml($xmlContent)
                
                $nsmgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                $nsmgr.AddNamespace("upnp", "urn:schemas-upnp-org:device-1-0")
                
                $device = $xml.SelectSingleNode("//upnp:device", $nsmgr)
                
                if ($device) {
                    $deviceProps = @{
                        "deviceType" = "Device Type"
                        "friendlyName" = "Friendly Name"
                        "manufacturer" = "Manufacturer"
                        "manufacturerURL" = "Manufacturer URL"
                        "modelDescription" = "Model Description"
                        "modelName" = "Model Name"
                        "modelNumber" = "Model Number"
                    }
                    
                    foreach ($prop in $deviceProps.Keys) {
                        $node = $device.SelectSingleNode("upnp:$prop", $nsmgr)
                        if ($node) {
                            Write-Output-Location -location $location -message "`t-> $($deviceProps[$prop]): $($node.InnerText)"
                        }
                    }
                    
                    Write-Output-Location -location $location -message "`t-> Services:"
                    $services = $device.SelectNodes(".//upnp:service", $nsmgr)
                    
                    $foundIGD = $false
                    
                    if ($services) {
                        foreach ($service in $services) {
                            $serviceType = $service.SelectSingleNode("upnp:serviceType", $nsmgr).InnerText
                            $controlUrl = $service.SelectSingleNode("upnp:controlURL", $nsmgr).InnerText
                            $eventSubUrl = $service.SelectSingleNode("upnp:eventSubURL", $nsmgr).InnerText
                            $scpdUrl = $service.SelectSingleNode("upnp:SCPDURL", $nsmgr).InnerText
                            
                            Write-Output-Location -location $location -message "`t`t=> Service Type: $serviceType"
                            Write-Output-Location -location $location -message "`t`t=> Control: $controlUrl"
                            Write-Output-Location -location $location -message "`t`t=> Events: $eventSubUrl"
                            
                            $baseUri = [System.Uri]$location
                            $fullControlUrl = [System.Uri]::new($baseUri, $controlUrl).ToString()
                            $fullScpdUrl = [System.Uri]::new($baseUri, $scpdUrl).ToString()
                            
                            Write-Output-Location -location $location -message "`t`t=> API: $fullScpdUrl"
                            
                            if ($serviceType -match "WANIPConnection|WANPPPConnection") {
                                $foundIGD = $true
                                if (-not $OnlyLocation) {
                                    Write-Output-Location -location $location -message "`t[+] IGD port mapping available. Looking up current mappings..."
                                    Get-PortMappings -location $location -controlUrl $fullControlUrl -serviceType $serviceType
                                }
                            }
                        }
                    } else {
                        Write-Output-Location -location $location -message "`t[!] No services found"
                    }
                } else {
                    Write-Output-Location -location $location -message "`t[!] No device information found"
                }
                
                if ($OnlyIGD -and -not $foundIGD) {
                    $script:outputData.Remove($location)
                }
                
            }
            catch {
                Write-Output-Location -location $location -message "`t[!] Failed to parse XML response: $($_.Exception.Message)"
                if ($OnlyIGD) {
                    $script:outputData.Remove($location)
                }
            }
        }
        catch {
            Write-Output-Location -location $location -message "[!] Failed to connect to $location : $($_.Exception.Message)"
            if ($OnlyIGD) {
                $script:outputData.Remove($location)
            }
        }
    }
}

$OnlyLocation = $false
$OnlyIGD = $false
$ShowHelp = $false

foreach ($arg in $args) {
    switch ($arg) {
        { $_ -in @("-h", "--help") } { 
            $ShowHelp = $true 
            break
        }
        "--onlylocation" { 
            $OnlyLocation = $true 
        }
        "--onlyigd" { 
            $OnlyIGD = $true 
        }
        default {
            Write-Host "Unknown option: $arg"
            Write-Host $helpText
            exit 1
        }
    }
}

if ($ShowHelp) {
    Write-Host $helpText
    exit 0
}

$locations = Discover-PnPLocations

if (-not $OnlyLocation) {
    Write-Host "[+] Discovering UPnP locations"
}

if (-not $OnlyLocation) {
    Write-Host "[+] Discovery complete"
    Write-Host "[+] $($locations.Count) locations found:"
    foreach ($location in $locations) {
        Write-Host "`t-> $location"
    }
}
elseif ($locations.Count -eq 0) {
    Write-Host "[!] Found 0 locations"
}

Parse-UPnPLocations -locations $locations -OnlyIGD:$OnlyIGD -OnlyLocation:$OnlyLocation

if ($OnlyIGD) {
    if ($script:outputData.Count -eq 0) {
        Write-Host "[!] Found 0 locations with IGD port mapping available"
    }
    elseif (-not $OnlyLocation) {
        Write-Host "[+] Finding only IGD port mapping"
    }
}

foreach ($location in $script:outputData.Keys) {
    if ($OnlyLocation) {
        Write-Host "`t-> $location"
    }
    else {
        foreach ($message in $script:outputData[$location]) {
            Write-Host $message
        }
    }
}

if (-not $OnlyLocation) {
    Write-Host "[+] Fin."
}

<#
.SYNOPSIS
    UPnP Discovery and Information Script

.DESCRIPTION
    This script discovers and analyzes UPnP devices on the local network,
    providing detailed information about their services and capabilities.

.PARAMETER help
    Show this help message

.PARAMETER onlylocation
    Only print discovered UPnP locations

.PARAMETER onlyigd
    Only print IGD (Internet Gateway Device) related information

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File $(Split-Path -Leaf $PSCommandPath)
    Runs the script with default settings

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File $(Split-Path -Leaf $PSCommandPath) --onlylocation
    Only displays discovered UPnP locations

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File $(Split-Path -Leaf $PSCommandPath) --onlyigd
    Only displays IGD-related information

.NOTES
    Author: Your Name
    Version: 1.0
#> 