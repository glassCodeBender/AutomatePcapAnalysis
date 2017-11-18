package com.security.pcap

// import com.security.pcap.SearchRange

/**
  * Add information about common IP ranges in whois to speed up program
  */

object CommonIPs extends SearchRange {

  def checkList(ip: String) = {

    if(microsoft(ip)) Some{PageInfo(ip, "Microsoft Corporation", "Redmond", "WA", "One Microsoft Way", "98052", "US",
      "Varies", "https://whois.arin.net/rest/org/MSFT.html", "Microsoft Computers")}
    else if(psiNet(ip)) Some{PageInfo(ip, "PSINet, Inc.", "Washington D.C.", "DC", "2450 N Street NW",
      "20037", "US","38.0.0.0 - 38.255.255.255", "https://whois.arin.net/rest/org/PSI.html", "ISP from Virginia" )}
    else if(level3(ip)) Some{PageInfo("8.138.81.7", "Level 3 Communications, Inc.", "Broomfield", "CO",
      "1025 Eldoraade Blvd", "US", "80021", "8.0.0.0 - 8.255.255.255", "https://whois.arin.net/rest/org/LVLT.html",
      "ISP")}
    else if(ripe(ip)) Some{PageInfo(ip, "RIPE Network Coordination Centre", "Amsterdam", "North Holland", "P.O. Box 10096",
      "Netherlands","1001EB", "5.0.0.0 - 5.255.255.255", "https://whois.arin.net/rest/org/RIPE.html",
      "Regional internet registry for Europe, the Middle East, and Asia.")}
    else if(ibm(ip)) Some{PageInfo(ip, "IBM", "Research Triangle Park", "NC", "3039 Cornwallis Road", "27709-2195", "US",
      "9.9.10.0 - 9.255.255.255", "https://whois.arin.net/rest/org/IBM-1.html", "IBM Computers")}
    else if(hp(ip)) Some{PageInfo(ip, "Hewlett Packard", "Palo Alto", "CA", "3000 Hanover St.", "94304", "US",
      "16.0.0.0 - 16.255.255.255", "https://whois.arin.net/rest/org/HPE-15.html", "HP Computers")}
    else if(dod(ip)) Some{PageInfo(ip, "DoD Network Information Center", "Columbus", "OH", "3990 E. Broad Street",
      "93218", "US", "7.0.0.0 - 7.255.255.255", "https://whois.arin.net/rest/org/DNIC.html", "ISP Security")}
    else if(asiaPacific(ip)) Some{PageInfo(ip, "Asia Pacific Network Information Centre", "South Brisbane", "QLD",
      "PO Box 3646","4101", "AU", "1.0.0.0 - 1.255.255.255", "https://whois.arin.net/rest/org/APNIC.html", "ISP")}
    else if(google(ip)) Some{PageInfo(ip, "Google LLC", "Mountain View", "CA", "1600 Amphithreatre Parkway", "94043",
      "US", "varies", "https://whois.arin.net/rest/org/GOGL.html", "Google does a lot of stuff")}
    else if(netflix(ip)) Some{PageInfo(ip, "Netflix Streaming Services Inc.", "Wilmington", "DE", "1209 Orange Street",
      "19801", "US", "23.246.0.0 - 23.246.63.255", "https://whois.arin.net/rest/org/SS-144.html", "Streaming TV company")}
    else if(twitter(ip)) Some{PageInfo(ip, "Twitter Inc.", "San Francisco", "CA", "1355 Market Street","94103", "US",
      "199.59.148.0 - 199.59.151.255", "https://whois.arin.net/rest/org/TWITT.html", "Social media website company")}
    else if(akamai(ip)) Some{PageInfo(ip, "Akamai Technologies, Inc.", "Cambridge", "MA", "150 Broadway", "US", "02142",
      "23.32.0.0 - 23.67.255.255", "https://whois.arin.net/rest/org/AKAMAI.html", "Content Delivery Network")}
    else if(iana(ip)) Some{PageInfo(ip, "Internet Assigned Number Authority", "Los Angeles", "CA", "12025 Waterfront Drive",
      "US", "90292", "Varies", "https://whois.arin.net/rest/org/IANA.html", "Overseas global IP address allocation")}
    else if(apple(ip)) Some{PageInfo(ip, "Apple Inc.", "Cupertino", "CA", "20400 Stevens Creek Blvd., City Center Bldg 3",
      "US", "95014", "17.0.0.0 - 17.255.255.255", "https://whois.arin.net/rest/org/APPLEC-1-Z.html", "Apple Computers")}
    else if(fastly(ip)) Some{PageInfo(ip, "Fastly", "San Francisco", "CA", "PO Box 78266", "US", "94107",
      "151.101.0.0 - 151.101.255.255", "https://whois.arin.net/rest/org/SKYCA-3.html", "Content Delivery Network")}
    else if(github(ip)) Some{PageInfo(ip, "Github Inc.", "San Francisco", "CA", "88 Colin P Kelly Jr Street", "US",
      "94107", "192.30.252.0 - 192.30.255.255", "https://whois.arin.net/rest/org/GITHU.html",
      "Used by programmers to store and share code.")}
    else if(verizon(ip)) Some{PageInfo(ip, "MCI Communications Services, Inc. d/b/a Verizon Business", "Ashburn",
      "VA", "22001 Loudoun County Pkwy", "US", "20147", "72.21.80.0 - 72.21.95.255",
      "https://whois.arin.net/rest/org/MCICS.html", "American telecommunications company")}
    else if(amazon(ip)) Some{PageInfo(ip, "Amazon Inc.", "Seattle", "WA", "", "US or IE", "", "Varies",
      "https://whois.arin.net/rest/org/AT-88-Z.html",
      "Amazon Technologies, Amazon.com Inc. or Amazon Data Services Ireland Limited" ) }
    else if(twc(ip)) Some{PageInfo(ip, "Time Warner Cable Internet LLC", "Herndon", "VA", "13820 Sunrise Valley Drive",
    "US", "20171", "72.176.0.0 - 72.191.255.255", "https://whois.arin.net/rest/org/RRSW.html", "American Telecom Company")
    }
    else None

    /*
    Whois Results for 72.177.235.253
Name: Time Warner Cable Internet LLC
Street: 13820 Sunrise Valley Drive
City: Herndon
State: VA
Postal Code: 20171
Country: US
IP Address Range: 72.176.0.0 - 72.191.255.255
Whois Registration Info URL: https://whois.arin.net/rest/org/RRSW.html


     */

    /*
        NEW

        Whois Results for 162.247.242.19
    Name: New Relic
    Street: 188 Spear Street, Suite 1200
    City: San Francisco
    State: CA
    Postal Code: 94105
    Country: US
    IP Address Range: 162.247.240.0 - 162.247.243.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/NR-18.html

    Whois Results for 74.121.138.59
    Name: MediaMath Inc
    Street: 150 Greenwich St, Floor 45
    City: New York
    State: NY
    Postal Code: 10007
    Country: US
    IP Address Range: 74.121.136.0 - 74.121.143.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/MEDIA-143.html

    Whois Results for 204.2.197.211
    Name: NTT America, Inc.
    Street: 8300 E Maplewood Ave.&#13;
    City: Greenwood Village
    State: CO
    Postal Code: 80111
    Country: US
    IP Address Range: 204.0.0.0 - 204.3.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/NTTAM-1.html



    Whois Results for 50.97.55.58
    Name: SoftLayer Technologies Inc.
    Street: 4849 Alpha Rd.
    City: Dallas
    State: TX
    Postal Code: 75244
    Country: US
    IP Address Range: 50.97.0.0 - 50.97.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/SOFTL.html


    Whois Results for 69.172.216.58
    Name: Saferoute Incorporated
    Street: 15 Cliff Street
    City: New York
    State: NY
    Postal Code: 10038
    Country: US
    IP Address Range: 69.172.216.0 - 69.172.216.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/SAFER-1.html


    # Marketing firm
    Whois Results for 67.226.210.14
    Name: Tremor Video
    Street: 1501 Broadway
    City: New York
    State: NY
    Postal Code: 10036
    Country: US
    IP Address Range: 67.226.210.0 - 67.226.211.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/TV-56.html


    # web hosting company
    Whois Results for 104.151.233.18
    Name: Enzu Inc
    Street: 10120 S Eastern Ave&#13;
    City: Henderson
    State: NV
    Postal Code: 89052
    Country: US
    IP Address Range: 104.151.0.0 - 104.151.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/ENZUI.html


    Whois Results for 63.140.33.238
    Name: Adobe Systems Inc.
    Street: 3900 Adobe Way
    City: Lehi
    State: UT
    Postal Code: 84043
    Country: US
    IP Address Range: 63.140.32.0 - 63.140.63.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/AS.html

    Whois Results for 152.163.13.79
    Name: AOL Inc.
    Street: 22000 AOL Way
    City: Dulles
    State: VA
    Postal Code: 20166
    Country: US
    IP Address Range: 152.163.0.0 - 152.163.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/AOLIN-1.html

    Whois Results for 68.67.148.63
    Name: AppNexus, Inc
    Street: 28 23rd Street&#13;
    City: New York
    State: NY
    Postal Code: 10010
    Country: US
    IP Address Range: 68.67.128.0 - 68.67.191.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/APPNE.html


    Whois Results for 63.241.108.103
    Name: CERFnet
    Street: 5738 Pacific Center Blvd
    City: San Diego
    State: CA
    Postal Code: 92121
    Country: US
    IP Address Range: 63.240.0.0 - 63.242.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/CERF.html


    Whois Results for 192.225.158.2
    Name: ThreatMetrix Inc.
    Street: 160 W Santa Clara Ave&#13;
    City: Santa Clara
    State: CA
    Postal Code: 95113
    Country: US
    IP Address Range: 192.225.156.0 - 192.225.159.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/THREA-1.html


    Whois Results for 108.174.11.65
    Name: LinkedIn Corporation
    Street: 2029 Stierlin Court
    City: Mountain View
    State: CA
    Postal Code: 94043
    Country: US
    IP Address Range: 108.174.0.0 - 108.174.15.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/LINKE-1.html



    Whois Results for 64.156.167.112
    Name: Conversant, Inc.
    Street: 30699 Russell Ranch Road Suite 250
    City: Westlake Village
    State: CA
    Postal Code: 91361
    Country: US
    IP Address Range: 64.156.167.0 - 64.156.167.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/VALUEC-5.html


    Whois Results for 23.111.11.83
    Name: Nobis Technology Group, LLC
    Street: 5350 East High Street&#13;
    City: Phoenix
    State: AZ
    Postal Code: 85054
    Country: US
    IP Address Range: 23.111.8.0 - 23.111.11.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/NTGL.html




    Whois Results for 204.2.250.100
    Name: NTT America, Inc.
    Street: 8300 E Maplewood Ave.&#13;
    City: Greenwood Village
    State: CO
    Postal Code: 80111
    Country: US
    IP Address Range: 204.0.0.0 - 204.3.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/NTTAM-1.html



    Whois Results for 157.240.17.18
    Name: Facebook, Inc.
    Street: 1601 Willow Rd.
    City: Menlo Park
    State: CA
    Postal Code: 94025
    Country: US
    IP Address Range: 157.240.0.0 - 157.240.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/THEFA-3.html


    Whois Results for 45.60.31.34
    Name: Incapsula Inc
    Street: 3400 Bridge Parkway, Suite 200
    City: Redwood Shores
    State: CA
    Postal Code: 94065
    Country: US
    IP Address Range: 45.60.0.0 - 45.60.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/INCAP-5.html



    Whois Results for 173.241.244.143
    Name: OPENX TECHNOLOGIES, INC.
    Street: 888 East Walnut Street&#13;
    City: Pasadena
    State: CA
    Postal Code: 91101
    Country: US
    IP Address Range: 173.241.240.0 - 173.241.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/OPENX.html



    Whois Results for 208.111.178.38
    Name: Limelight Networks, Inc.
    Street: 222 South Mill Ave.&#13;
    City: Tempe
    State: AZ
    Postal Code: 85281
    Country: US
    IP Address Range: 208.111.128.0 - 208.111.191.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/LLNW.html




    Whois Results for 45.54.60.3
    Name: NetActuate, Inc
    Street: 8605 Santa Monica Blvd #25273
    City: Los Angeles
    State: CA
    Postal Code: 90069
    Country: US
    IP Address Range: 45.54.0.0 - 45.54.127.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/NETAC-4.html


    Whois Results for 104.16.42.17
    Name: Cloudflare, Inc.
    Street: 101 Townsend Street
    City: San Francisco
    State: CA
    Postal Code: 94107
    Country: US
    IP Address Range: 104.16.0.0 - 104.31.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/CLOUD14.html


    Whois Results for 152.195.54.201
    Name: ANS Communications, Inc
    Street: 22001 Loudoun County Parkway
    City: Ashburn
    State: VA
    Postal Code: 20147
    Country: US
    IP Address Range: 152.176.0.0 - 152.199.255.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/ANS.html



    Whois Results for 205.203.132.65
    Name: Dow Jones-Telerate
    Street: 4300 North Route 1&#13;
    City: South Brunswick
    State: NJ
    Postal Code: 08852
    Country: US
    IP Address Range: 205.203.96.0 - 205.203.159.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/DOWJON.html



    Whois Results for 104.238.145.141
    Name: Vultr Holdings, LLC
    Street: 2323 Bryan St.
    City: Dallas
    State: TX
    Postal Code: 75201
    Country: US
    IP Address Range: 104.238.144.0 - 104.238.145.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/VHL-104.html


    Whois Results for 192.33.31.80
    Name: Instart Logic, Inc
    Street: 450 Lambert Ave
    City: Palo Alto
    State: CA
    Postal Code: 94306
    Country: US
    IP Address Range: 192.33.24.0 - 192.33.31.255
    Whois Registration Info URL: https://whois.arin.net/rest/org/IL-69.html

    */

  } // END checkList()

  def checkVecRange(ip: String, vec: Vector[(String, String)]): Boolean = {
    val bools = for(value <- vec) yield searchIpRange(ip, value._1, value._2)
    if (bools.contains(true)) true
    else false
  } // END checkVecRange()
  def twc(ip: String) = {

    val range = ("72.176.0.0", "72.191.255.255")
    searchIpRange(ip, range._1, range._2)

  } // END twc()

  def microsoft(ip: String) = {
    val ranges = Vector(("137.116.0.0", "137.116.255.255"), ("104.208.0.0", "104.215.255.255"),
      ("64.4.0.0", "64.4.63.255"), ("40.74.0.0", "40.125.127.255"), ("65.52.0.0", "65.55.255.255"),
      ("104.40.0.0", "104.47.255.255"), ("40.74.0.0", "40.125.127.255"), ("13.64.0.0", "13.107.255.255"),
      ("23.96.0.0", "23.103.255.255"), ("157.54.0.0", "157.60.255.255"), ("131.253.61.0", "131.253.255.255")
    )

    checkVecRange(ip, ranges)
  } // END microsoft()

  def ge(ip: String): Boolean = {
    val ranges = ("3.0.0.0", "3.225.255.155")
    searchIpRange(ip, ranges._1, ranges._2)
  }
  def level3(ip: String): Boolean = {
    val range = Vector(("4.0.0.0", "4.255.255.255"), ("8.0.0.0", "8.255.255.255"))
    checkVecRange(ip, range)
  }
  def ripe(ip: String): Boolean = {
    val range = Vector(("92.0.0.0", "92.255.255.255"), ("2.0.0.0", "2.255.255.255"), ("57.0.0.0", "57.255.255.255"),
      ("51.0.0.0", "51.255.255.255"),("31.0.0.0", "31.255.255.255"), ("5.0.0.0", "5.255.255.255"))
    checkVecRange(ip, range)
  }

  def ibm(ip: String): Boolean = {
    val range = ("9.9.10.0", "9.255.255.255")
    searchIpRange(ip, range._1, range._2)
  }

  def amazon(ip: String): Boolean = {
    // Amazon Technologies
    val range = Vector(("52.192.0.0", "52.223.255.255"), ("52.84.0.0", "52.95.255.255"),
      ("52.84.0.0", "52.95.255.255"), ("52.208.0.0", "52.215.255.255"), ("54.184.0.0", "54.187.255.255"),
      ("54.240.0.0", "54.255.255.255"), ("52.30.0.0", "52.31.255.255"), ("52.208.0.0", "52.215.255.255"))

    checkVecRange(ip, range)

  } // END amazon()

  def hp(ip: String): Boolean = {

    val range = ("16.0.0.0", "16.255.255.255")
    searchIpRange(ip, range._1, range._2)
  }

  def dod(ip: String): Boolean = {

    val range = ("7.0.0.0", "7.255.255.255")

    searchIpRange(ip, range._1, range._2)
  }

  def psiNet(ip: String): Boolean = {
    val range = ("38.0.0.0", "38.255.255.255")

    searchIpRange(ip, range._1, range._2)
  }

  def asiaPacific(ip: String): Boolean = {

    val range = Vector(("1.0.0.0", "1.255.255.255"), ("39.0.0.0", "39.255.255.255"))
    checkVecRange(ip, range)
  }
  def google(ip: String): Boolean = {

    val range = Vector(("64.233.160.0", "64.233.191.255"), ("216.58.192.0", "216.58.223.255"),
      ("172.217.0.0", "172.217.255.255"))

    checkVecRange(ip, range)
  }

  def netflix(ip: String): Boolean = {
    val range = ("23.246.0.0", "23.246.63.255")
    searchIpRange(ip, range._1, range._2)
  } // END netflix()

  def twitter(ip: String): Boolean = {
    val range = Vector(("104.244.40.0", "104.244.47.255"), ("199.59.148.0", "199.59.151.255"))

    checkVecRange(ip, range)

  } // END twitter()

  def akamai(ip: String): Boolean = {

    val range = Vector(("23.32.0.0", "23.67.255.255"), ("23.32.0.0", "23.67.255.255"),
      ("23.192.0.0", "23.223.255.255"), ("23.192.0.0", "23.223.255.255"), ("23.72.0.0", "23.79.255.255"),
      ("184.24.0.0", "184.31.255.255"), ("104.64.0.0", "104.127.255.255")
    )
    checkVecRange(ip, range)
  } // END akamai

  def iana(ip: String): Boolean = {
    val range = Vector(("224.0.0.0", "239.255.255.255"), ("240.0.0.0", "255.255.255.255"),("0.0.0.0", "0.255.255.255"))
    checkVecRange(ip, range)
  }

  def apple(ip: String): Boolean = {
    val range = ("17.0.0.0", "17.255.255.255")
    searchIpRange(ip, range._1, range._2)
  }
  def github(ip: String): Boolean = {
    val range = ("192.30.252.0", "192.30.255.255")
    searchIpRange(ip, range._1, range._2)
  }

  def fastly(ip: String): Boolean = {
    val range = ("151.101.0.0", "151.101.255.255")
    searchIpRange(ip, range._1, range._2)
  }
  def verizon(ip: String): Boolean = {
    val range = ("72.21.80.0", "72.21.95.255")
    searchIpRange(ip, range._1, range._2)
  }
  def usps(ip: String): Boolean = {
    val range = ("39.0.0.0", "39.255.255.255")
    searchIpRange(ip, range._1, range._2)
  }

} // END CommonIPs

