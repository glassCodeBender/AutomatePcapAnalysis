package com.security.pcap
// import sys.process._
import scala.collection.immutable.TreeMap
import scala.collection.mutable.ArrayBuffer
import scala.io.Source
// import java.util.Calendar

import scala.util.Try

class AutomatePcapAnalysis(pcapFile: String) {

  def run(): Unit = {

    val read = readFile(pcapFile)
    if(read.isFailure) {
      println("Failed to read file...")
      System.exit(1)
    }
    else{

      val csvVec: Vector[String] = read.get
      /** Create single array of column headers*/
      val colHeaders: Array[String] = csvVec.head.split(',')





      /** Remove headers and create 2d array of values */
      val csvContent = csvVec.drop(1).map(_.split(','))

      var buff = ArrayBuffer[(Int, String)]()
      var i = 0
      while(i < csvContent(2).size){
        buff += (i -> csvContent(2)(i))
        i = i + 1
      }

      println("Printing values and indices")
      buff.foreach(println)

      /**
        * Eventually all this logic needs it's own method.
        */
      /** Grab content from various ip address columns */
      val ipSrc: Vector[String] = csvContent.map(x => x(8)).distinct
      val ipDst: Vector[String] = csvContent.map(x => x(9)).distinct

      println("ipSrc size: " + ipSrc.size)
      println("ipDst size: " + ipDst.size)

      println("Printing ipSrc: ")
      ipSrc.foreach(println)
      println("Printing ipDst: ")
      ipDst.foreach(println)

      val concatIp = ipDst ++: ipSrc

      val distinctIps: Vector[String] = concatIp.distinct

      /** Figure out which ports were used */

      // Need to make sure TCP Port exists or else we assign a different value to it.
      val portsSrc = csvContent.map(x => Try(x(23)).getOrElse("000")).distinct
      val portsDst = csvContent.map(x => Try(x(24)).getOrElse("000")).distinct
      // Remove quotes
      val tcpPortSrc = portsSrc.drop(1).dropRight(1)
      val tcpPortDst = portsDst.drop(1).dropRight(1)

      println("Printing source ports...\n")
      portsSrc.drop(1).foreach(println)
      println("Printing destination ports...\n")
      portsDst.drop(1).foreach(println)

      val pSrc = csvContent.map(x => Try(x(13)).getOrElse("000")).distinct
      val pDst = csvContent.map(x => Try(x(14)).getOrElse("000")).distinct
      val udpPortSrc = pSrc.drop(1).dropRight(1)
      val udpPortDst = pDst.drop(1).dropRight(1)

      println("Printing UDP source ports...\n")
      udpPortSrc.drop(1).foreach(println)
      println("Printing UDP destination ports...\n")
      udpPortDst.drop(1).foreach(println)

      // val regex = "\"".r
      // val cleanIps = distinctIps.map(x => regex.replaceAllIn(x, ""))

      /** Removing quotes because the regex won't work! */
      val clean = distinctIps.map(_.drop(1))
      val cleanerIps = clean.map(_.dropRight(1))

      /** Filter out local IP addresses */
      val filterOutLocal = cleanerIps.filterNot(_.startsWith("192"))
        .filterNot(_.startsWith("10"))
        .filterNot(_.startsWith("172"))

      val pageInfoFound: Vector[PageInfo] = whoIsQuery(cleanerIps)

      println("Printing Page Info Found")

      pageInfoFound.foreach(println)

      println("Awesome! Page information printed.\n\nNow we're going to check for commonly attacked ports...\n\n")




      /**
        * grab common values and put in data structure.
        * grab distinct values and put in two other data structures.
        */

      // THESE ARE GRABBING PORT NUMBERS
      // val udpSrc: Vector[String] = csvContent.map(x => x(13)).distinct
      // val udpDst: Vector[String] = csvContent.map(x => x(14)).distinct

      // val udpSrcDiff = udpSrc.diff(udpDst)
      // println("Print udpSrcDiff")
      // udpSrcDiff.foreach(println)

      // val udpDstDiff = udpDst.diff(udpSrc)
      // println("Print udpDstDiff")
      // udpDstDiff.foreach(println)

      /**
        * grab common values and put in data structure.
        * grab distinct values and put in two other data structures.
        */

      // Skipping port numbers for now

      /**
        * Need to do checking to see which values use other protocols
        *
        * Then perform WhoIs lookup
        */


      /**
        * COLUMNS:
        *
        * WE NEED ALL OF THESE FOR FUTURE ANALYSIS LATER
        *
        * 0-frame.time,
        * 1-ip.version,
        * 2-ip.id,
        * 3-ip.len,
        * 4-ip.proto,
        * 5-ip.ttl,
        * 6-ip.flags,
        * 7-ip.src,
        * 8-ip.dst,
        * 9-icmp.code,
        * 10-icmp.type,
        * 11-icmp.resptime,
        * 12-udp.srcport,
        * 13-udp.dstport,
        * 14-dns.id,
        * 15-dns.qry.
        * 16-type,
        * 17-dns.resp.type,
        * 18-dns.qry.name,
        * 19-dns.a, Address
        * 20-tcp.stream,
        * 21-tcp.seq,
        * 22-tcp.flags,
        * 23-tcp.srcport,
        * 24-tcp.dstport,
        * 25-http.request.method,
        * 26-http.host,
        * 27-http.request.version,
        * 28-http.user_agent,
        * 29-http.server,
        * 30-http.response.code,
        * 31-http.response.phrase
        */




    } // END else


  } // END main()

  private[this] def whoIsQuery(vec: Vector[String]): Vector[PageInfo] = {
    val whoIsResults: Vector[PageInfo] = for(str <- vec) yield getWhoIs(str)

    return whoIsResults
  } // END whoIs()

  private[this] def getWhoIs(str: String): PageInfo = {
    val whois = new WhoIs(str)
    val result = Try(whois.query()).getOrElse(PageInfo(str, "Failed", "Failed", "Failed", "", "","","",""))

    return result
  }

  def readFile(pcap: String): Try[Vector[String]] = {
    Try(Source.fromFile(pcap).getLines.toVector)
  } // END readFile()

  private[this] def getCommonTargetPort(portNo: String): String = {

    // Check for the following ports
    val commonTargetPorts = Map("20" -> "ftp", "5060" -> "SIP", "554" -> "rtsp", "17185" -> "soundsvirtual",
      "3369" -> "satvid-datalnk", "1883" -> "IBM MQSeries Scada", "333" -> "Texas Security", "2080" -> "autodesk-nlm",
      "5432" -> "postgres database server", "4289" -> "VRLM Multi User System",
      "3377" -> "Cogsys Network License Manager", "47808" -> "bacnet", "4899" -> "Remote Administrator Default Port",
      "500" -> "VPN Key Exchange", "3366" -> "Creative Partner", "3339" -> "anet-l OMF data l",
      "563" -> "nntp over TLS protocol", "2003" -> "cfingerd GNU Finger", "3370" -> "satvid Video Data Link",
      "222" -> "Berkeley rshd with SPX auth", "3281" -> "sysopt", "3368" -> "satvid Video Data Link",
      "7070" -> "ARCP", "3421" -> "Bull Apprise Portmapper", "4500" -> "sae-urn",
      "16992" -> "Intel AMT remote managment", "5800" -> "VNC", "3277" -> "awg proxy",
      "502" -> "asl-appl-proto", "212" -> "SCIENTA-SSDB", "3378" -> "WSICOPY", "3459" -> "Eclipse 2000 Trojan",
      "3328" -> "Eaglepoint License Manager", "5984" -> "couchdb", "3360" -> "kv-server", "3348" -> "Pangolin Laser",
      "3052" -> "APCPCNS", "3343" -> "MS Cluster Net", "44444" -> "Prosiak Trojan", "3286" -> "E-Net",
      "22222" -> "Donald Dick Trojan", "3353" -> "fatpipe", "3355" -> "Ordinox Database", "513" -> "Grlogin Trojan"
    )

    /** Need to make sure this returns something if not found. */
    return Try(commonTargetPorts(portNo)).getOrElse("None")
  } // END getCommonTargetPort()

  /** Pass a port number to check risk associated w/ port number */
  private[this] def getPortRisk(portNo: String): String = {

    /** Map of ports commonly used by hackers. List should include more ports.
      * Values based on SANS port report https://isc.sans.edu/port
      */
    val probPorts = TreeMap[String, String]("4946" -> "high", "4344" -> "medium", "4331" -> "medium", "2525" -> "high",
      "513" -> "critical", "2087" -> "medium", "5060" -> "high", "1234" -> "high", "3097" -> "medium",
      "30000" -> "critical", "54321" -> "critical", "33333" -> "critical", "5800" -> "medium", "3459" -> "critical",
      "44444" -> "critical", "22222" -> "critical", "491" -> "medium",
      "3575" -> "critical", "3573" -> "high", "3569" -> "high", "3566" -> "critical", "3558" -> "high",
      "3552" -> "high", "3551" -> "high", "3545" -> "high", "3509" -> "high", "3074" -> "low", "2702" -> "critical",
      "2120" -> "medium", "1656" -> "low", "1613" -> "critical", "655" -> "medium", "3074" -> "low",
      "1749" -> "medium", "2120" -> "low", "2273" -> "low", "3558" -> "high", "3571" -> "high", "4344" -> "low",
      "4946" -> "medium", "5355" -> "critical", "5827" -> "low", "6882" -> "medium", "6957" -> "low", "7834" -> "low",
      "9343" -> "low", "10034" -> "low", "10070" -> "critical", "11460" -> "low", "10550" -> "low", "11786" -> "low",
      "11868" -> "low", "12632" -> "low", "13600" -> "low", "14427" -> "low", "14501" -> "medium", "14502" -> "medium",
      "14503" -> "medium", "14504" -> "medium", "14506" -> "medium", "14518" -> "medium", "14519" -> "medium",
      "14546" -> "medium", "14547" -> "medium", "14559" -> "medium", "14562" -> "medium", "14576" -> "medium",
      "14580" -> "medium", "14581" -> "medium", "14582" -> "medium", "14585" -> "low", "14814"  -> "low",
      "14955" -> "medium", "15714" -> "low", "16183" -> "low","17225" -> "low", "17500" -> "critical",
      "17730" -> "medium", "18170" -> "low", "19120" -> "low", "19451" -> "low", "19820" -> "low", "19948" -> "low",
      "19999" -> "low", "20012"  -> "low", "20707" -> "low", "21027" -> "critical", "21646" -> "low", "21715" -> "low",
      "22238" -> "low", "22328" -> "low", "24404" -> "low", "24542" -> "low", "24863" -> "low", "25441" -> "low",
      "26431" -> "low", "26858" -> "low", "27719" -> "low", "27745" -> "low", "27969" -> "low", "28607" -> "low",
      "29294" -> "low", "29440" -> "high", "30516" -> "low", "31101" -> "high", "31695" -> "low", "31949" -> "low",
      "32172" -> "low", "32414" -> "critical", "33063" -> "low", "33120" -> "low", "33331" -> "low", "33978" -> "low",
      "34425" -> "low", "34518" -> "low", "34751" -> "low", "34885" -> "low", "35166" -> "low", "35366" -> "low",
      "35393" -> "low", "35899" -> "low", "35902" -> "low", "36123" -> "critical", "36138" -> "low", "36181" -> "low",
      "36289" -> "medium", "36538" -> "medium", "36620" -> "high", "36787" -> "low", "36817" -> "low", "37087" -> "low",
      "37558" -> "low", "38250" -> "low", "38418" -> "low", "38610" -> "low", "38857" -> "low", "38972" -> "medium",
      "38979" -> "low", "38972" -> "medium", "38982" -> "medium", "39203" -> "low", "39395" -> "medium",
      "39571" -> "low", "39804" -> "medium", "40089" -> "low", "40297" -> "low", "40400" -> "low", "40483" -> "low",
      "40778" -> "low", "40902" -> "low", "41712" -> "low", "41995" -> "medium", "42193" -> "low", "42866" -> "medium",
      "43312" -> "medium", "43884" -> "low", "45827" -> "low", "45977" -> "low", "46573" -> "medium",
      "47123" -> "medium", "47554" -> "low", "48392" -> "low", "49387" -> "low", "49438" -> "medium",
      "49491" -> "low", "49792" -> "low", "50076" -> "low", "50086" -> "low", "50088" -> "medium", "51533" -> "high",
      "51799" -> "low", "52622" -> "low", "52656" -> "high", "53773" -> "low", "54191" -> "low", "54256" -> "critical",
      "54373" -> "low", "55733" -> "medium", "56168" -> "low", "57325" -> "low", "57621" -> "critical",
      "57925" -> "medium", "58067" -> "low", "58085" -> "low", "58180" -> "low", "58231" -> "high", "58554" -> "low",
      "58558" -> "medium", "58582" -> "low", "58838" -> "low", "58842" -> "low", "58975" -> "low", "59107" -> "medium",
      "59134" -> "low", "49141" -> "low", "59163" -> "low", "59206" -> "medium", "59566" -> "low", "59707" -> "high",
      "59789" -> "low", "59873" -> "low", "59912" -> "medium", "60527" -> "low", "61134" -> "medium", "61905" -> "high",
      "62581" -> "low", "63656" -> "low", "63747" -> "low", "63800" -> "medium", "63867" -> "medium", "64076" -> "low",
      "64549" -> "medium", "65285" -> "low", "350" -> "low", "577" -> "low", "857" -> "low",
    ) // END probPorts treemap

    return Try(probPorts(portNo)).getOrElse("None")
  } // END getProbPort()


} // END AutomatePcapAnalysis
