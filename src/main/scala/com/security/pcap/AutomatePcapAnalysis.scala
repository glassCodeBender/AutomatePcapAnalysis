package com.security.pcap

// import sys.process._
import java.sql.{Connection, DriverManager, Statement}

import com.security.pcap.GeolocationInfo.ipToLong

import scala.collection.immutable.TreeMap
import scala.collection.mutable.ArrayBuffer
import scala.io.Source
import scala.collection.mutable._
import net.liftweb.json._
import net.liftweb.json.Serialization.write

// import java.util.Calendar

import scala.util.Try

final case class PcapAnalysis( riskyPorts: Vector[Array[String]],
                               commonTarget: Vector[Array[String]],
                               sessions: Vector[Array[String]],
                               ipInfo: Vector[PageInfo]
                             )

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
      val colHeaders: Array[String] = csvVec.head.split('\t')

      println("Column Headers: \n")
      colHeaders.foreach(println)

      /** Remove headers and create 2d array of values */
      val csvContent: Vector[Array[String]] = csvVec.tail.map(_.split('\t'))

      /** Look for ports commonly attacked by adversaries. */
      // val (risk, commonTargets): (Vector[Array[String]], Vector[Array[String]]) = portRiskAnalysis(csvContent)

      /** Check for the beginning of sessions. Might miss some if sniffer started after session began.*/
      val sessBeginning  = checkSessionBeginnings(csvContent)

      /** Get information about the IP addresses. */
      val distinctIps = grabIps(csvContent)


      /** Whois Lookup Stuff */
      val ipInfo: Vector[IpInfo] = whoisAnalysis(distinctIps)


      println("\n\nPrinting geolocation info\n\n")
      val combinedWhoIsGeoLoc = GeolocationInfo.run(distinctIps, ipInfo)


      /**
        * Now we need to clean it all up and combine it.
        */


      val sessBegin = sessBeginning :+ colHeaders

      // val findings = PcapAnalysis(risk, commonTargets, sessBegin, ipInfo)

      //val jsonFindings = createJson(findings)


    } // END else
  } // END main()

  private[this] def grabIps(csvContent: Vector[Array[String]]): Vector[String] = {

    /** Grab content from various ip address columns */
    val ipSrc: Vector[String] = csvContent.map(x => x(7)).distinct
    val ipDst: Vector[String] = csvContent.map(x => x(8)).distinct

    println("ipSrc size: " + ipSrc.size)
    println("ipDst size: " + ipDst.size)

    println("Printing ipSrc: ")
    ipSrc.foreach(println)
    println("Printing ipDst: ")
    ipDst.foreach(println)

    val concatIp = ipDst ++: ipSrc

    val distinctIps: Vector[String] = concatIp.distinct

    // val regex = "\"".r
    // val cleanIps = distinctIps.map(x => regex.replaceAllIn(x, ""))

    /** Removing quotes because the regex won't work! */
    val clean = distinctIps.map(_.drop(1))
    val cleanerIps: Vector[String] = clean.map(_.dropRight(1))
    cleanerIps
  }

  private[this] def createJson(pcapAnalysis: PcapAnalysis): String = {

    implicit val formats = DefaultFormats
    val jsonStr: String = write(pcapAnalysis)
    println("Printing test json string")
    // println(jsonStr)

    return jsonStr
  } // END createJson()

  /** Checks ports against the most common attacked ports. */
  private[this] def portRiskAnalysis(csvContent: Vector[Array[String]]):
                                                      (Vector[Array[String]], Vector[Array[String]]) ={

    /** Figure out which ports were used */

    // Need to make sure TCP Port exists or else we assign a different value to it.
    val tcpPortSrc = csvContent.map(x => Try(x(22)).getOrElse("000")).distinct
    val tcpPortDst = csvContent.map(x => Try(x(23)).getOrElse("000")).distinct
    // Remove quotes
    //val tcpPortSrc = portsSrc.drop(1).dropRight(1)
    //val tcpPortDst = portsDst.drop(1).dropRight(1)

    println("Printing source ports...\n")
    tcpPortSrc.drop(1).foreach(println)
    println("Printing destination ports...\n")
    tcpPortDst.drop(1).foreach(println)

    /** Cleaning up ports */
    val udpPortSrc = csvContent.map(x => Try(x(11)).getOrElse("000")).distinct.filterNot(_.contains("000"))
    val udpPortDst = csvContent.map(x => Try(x(12)).getOrElse("000")).distinct.filterNot(_.contains("000"))
    // val udpPortSrc = pSrc.drop(1).dropRight(1)
    // val udpPortDst = pDst.drop(1).dropRight(1)

    println("Printing UDP source ports...\n")
    udpPortSrc.drop(1).foreach(println)
    println("Printing UDP destination ports...\n")
    udpPortDst.drop(1).foreach(println)

    /** TCP STUFF */

      /** TCP Common Targets */
    val tcpDstCommonTargets = checkCommonTargets(tcpPortDst)
    val tcpSrcCommonTargets = checkCommonTargets(tcpPortSrc)

    println("\nPrinting possible problem ports...\n\n")
    println("NOTE: Most port numbers can be used by any application. The rating is based on commonly attacked ports.\n" +
    "Medium and Low Risk classifications are very common.\n")

    val tcpDst: Vector[(String, String)] = tcpDstCommonTargets.filterNot(x => x._2.contains("None"))
    if (tcpDst.nonEmpty) for(value <- tcpDst) println("Port: " + value._1 + " Classification: " + value._2)
    val tcpDstCommonReturn: Vector[Array[String]] = tcpDst.map(x => Array("tcpDst", x._1, x._2))

    val tcpSrc: Vector[(String, String)]  = tcpSrcCommonTargets.filterNot(x => x._2.contains("None"))
    if (tcpSrc.nonEmpty) for(value <- tcpSrc) println("Port: " + value._1 + " Classification: " + value._2)
    val tcpSrcCommonReturn: Vector[Array[String]] = tcpSrc.map(x => Array("tcpSrc", x._1, x._2))

    /** TCP Port Risk */
    val tcpDstPortRisk = checkPortRisk(tcpPortDst)
    val tcpSrcPortRisk = checkPortRisk(tcpPortSrc)

    val tcpDstRisk: Vector[(String, String)]  = tcpDstPortRisk.filterNot(x => x._2.contains("None"))
    if (tcpDstRisk.nonEmpty) for(value <- tcpDstRisk) println("Port: " + value._1 + " Risk: " + value._2)

    val tcpDstRiskReturn: Vector[Array[String]] = tcpDstRisk.map(x => Array("tcppDst", x._1, x._2))

    val tcpSrcRisk: Vector[(String, String)]  = tcpSrcPortRisk.filterNot(x => x._2.contains("None"))

    if (tcpSrcRisk.nonEmpty) for(value <- tcpSrcRisk) println("Port: " + value._1 + " Risk: " + value._2)
    val tcpSrcRiskReturn: Vector[Array[String]] = tcpSrcRisk.map(x => Array("tcpSrc", x._1, x._2))

    /** UDP Common Tagets */
    val udpDstCommonTargets = checkCommonTargets(udpPortDst)
    val udpSrcCommonTargets = checkCommonTargets(udpPortSrc)

    val udpDstTargets = udpDstCommonTargets.filterNot(x => x._2.contains("None"))
    if (udpDstTargets.nonEmpty) for(value <- udpDstTargets) println("Port: " + value._1 + " Classification: " + value._2)
    val udpDstCommonReturn: Vector[Array[String]] = udpDstTargets.map(x => Array("tcpDst", x._1, x._2))

    val udpSrcTargets: Vector[(String, String)]  = udpSrcCommonTargets.filterNot(x => x._2.contains("None"))
    if (udpSrcTargets.nonEmpty) for(value <- udpSrcTargets) println("Port: " + value._1 + " Classification: " + value._2)
    val udpSrcCommonReturn: Vector[Array[String]] = udpSrcTargets.map(x => Array("tcpSrc", x._1, x._2))

    val commonTargetReturn: Vector[Array[String]] = {
      tcpSrcCommonReturn ++: tcpDstCommonReturn ++: udpDstCommonReturn ++: udpSrcCommonReturn
    }

    /** UDP Port Risk */

    val udpDstPortRisk = checkPortRisk(udpPortDst)
    val udpSrcPortRisk = checkPortRisk(udpPortSrc)

    val udpDst: Vector[(String, String)]  = udpDstPortRisk.filterNot(x => x._2.contains("None"))
     if (udpDst.nonEmpty) for(value <- udpDst) println("Port: " + value._1 + " Risk: " + value._2)

    val udpDstRiskReturn: Vector[Array[String]] = udpDst.map(x => Array("udpDst", x._1, x._2))

    val udpSrc: Vector[(String, String)]  = udpSrcPortRisk.filterNot(x => x._2.contains("None"))
    if (udpSrc.nonEmpty) for(value <- udpSrc) println("Port: " + value._1 + " Risk: " + value._2)
    val udpSrcRiskReturn: Vector[Array[String]] = udpSrc.map(x => Array("udpSrc", x._1, x._2))


    /** Print TCP Common Targets */
    // if (tcpDst.nonEmpty) for(value <- tcpDst) println("Port: " + value._1 + " Classification: " + value._2)
    // if (tcpSrc.nonEmpty) for(value <- tcpSrc) println("Port: " + value._1 + " Classification: " + value._2)

    /** Print UDP Common Targets */
    // if (udpSrc.nonEmpty) for(value <- udpSrc) println("Port: " + value._1 + " Classification: " + value._2)
    // if (udpDst.nonEmpty) for(value <- udpDst) println("Port: " + value._1 + " Classification: " + value._2)

    val riskReturn = tcpDstRiskReturn ++: tcpSrcRiskReturn ++: udpDstRiskReturn ++: udpSrcRiskReturn


    // val probs: Vector[Array[String]] = tcpDstReturn ++: tcpSrcReturn ++: udpDstReturn ++: udpSrcReturn

    return (riskReturn, commonTargetReturn)
  } // END portAnalysis()

  private[this] def checkSessionBeginnings(vec: Vector[Array[String]]): Vector[Array[String]] = {


    val tcpFlags = Map("0x00000002" -> "SYN", "0x00000012" -> "SYN+ACK", "0x00000010" -> "ACK",
    "0x00000018" -> "PSH+ACK", "0x00000011"-> "FIN+ACK", "0x00000019" -> "0x00000011", "0x00000019" -> "FIN+PSH+ACK",
    "0x00000004" -> "RST", "0x00000038" -> "RST", "0x00000038" -> "PSH+URG+ACK", "0x00000014" -> "RST+ACK")

    /** Changes the flag value. combines source and dest ips into a single field. */
    val sessionStarts = for{
      x <- vec
      if Try(x(21)).getOrElse("Blah") == "0x00000012"
    } yield Array(x(0), x(1), x(2), x(3), x(4),x(5), x(6), x(7), x(8), x(9),x(10), x(11), x(12),
      x(13), x(14),x(15), x(16), x(17), x(18), x(19), x(20), Try(x(21)).getOrElse("Other"), x(22), x(23))

    println("Printing Session Beginnings: \n\n")
    for(session <- sessionStarts) println(session.mkString(","))
    /*

    val sessionStarts = for{
      line <- fixedFlags
      if line(21) == "SYN"
    } yield line
*/
    return sessionStarts
  } // END checkSessionBeginnings
  private[this] def checkCommonTargets(vec: Vector[String]): Vector[(String, String)] ={

    val commonTargets = for(portNo <- vec) yield getCommonTargetPort(portNo)

    return commonTargets
  } // END checkCommonlyAttacked()

  private[this] def checkPortRisk(vec: Vector[String]): Vector[(String, String)] ={

    val commonTargets = for(portNo <- vec) yield getPortRisk(portNo)

    return commonTargets
  } // END checkCommonlyAttacked()

  private[this] def whoisAnalysis(csvContent: Vector[String]): Vector[IpInfo] = {

    /** This is for debugging */
    /*
    var buff = ArrayBuffer[(Int, String)]()
    var i = 0
    while(i < csvContent(2).size){
      buff += (i -> csvContent(2)(i))
      i = i + 1
    }

    // println("Printing values and indices")
    // buff.foreach(println)

    */

    /** Filter out local IP addresses */
    val filterOutLocal: Vector[String] = csvContent.filterNot(_.startsWith("192"))
      .filterNot(_.startsWith("10"))
      .filterNot(_.startsWith("172"))

    val checkKnown: Vector[Option[PageInfo]] = for(item <- filterOutLocal) yield CommonIPs.checkList(item)

    /** Remove None types from list. */
    val flatCheckKnown: Vector[PageInfo] = checkKnown.flatten
    /** Grab the ips we already have info for. */

    val ipsKnown = flatCheckKnown.map(_.ip)

    println("Printing known IPs")
    println(ipsKnown.size)
    ipsKnown.foreach(println)

    /** Get a list that includes only those we don't already have. */
    val diffIps: Vector[String] = filterOutLocal.diff(ipsKnown)
    println("Printing diffIps")
    println(diffIps.length)
    diffIps.foreach(println)
    /** Query IP addresses for unknown IPs*/
    // val newQuery = whoIsQuery(diffIps)

    /** Now we need to do a whois query for all the ips we don't know. */

      /** Find the difference between the two lists */

    val pageInfoFound: Vector[IpInfo] = whoIsQuery(diffIps)

    val allWhois: Vector[IpInfo] = pageInfoFound ++: flatCheckKnown

    println("Printing Page Info Found (allWhoIs):\n\n")

    allWhois.foreach(println)

    println("Awesome! Page information printed.\n\nNow we're going to check for commonly attacked ports...\n\n")


    return pageInfoFound
  } // END ipAnalysis()

  private[this] def whoIsQuery(vec: Vector[String]): Vector[IpInfo] = {
    val whoIsResults: Vector[PageInfo] = for(str <- vec) yield getWhoIs(str)

    val filteredWhois = whoIsResults.filter(x => x.getSuccess)

    addWhoisToDb(filteredWhois)

    return filteredWhois
  } // END whoIs()

  /** Add Result of Whois query to database */
  private[this] def addWhoisToDb(vec: Vector[PageInfo]) = {

    /** Set up SQL driver*/
    val path = "jdbc:sqlite:" + System.getProperty("user.dir") + "/pcaps/IP2GeoLoc.db"

    val connection: Connection = DriverManager.getConnection(path)

    val regex = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}".r
    val cleanedWhoIs = vec.filter(x => regex.findFirstIn(x.ip).getOrElse("Blah") != "Blah")
    val extraClean = cleanedWhoIs.filterNot(x => x.url.nonEmpty)

    for(value <- extraClean ) individualDbUpdate(value, connection)

    try{
      if(connection != null)
        connection.close()
    } catch{
      case e: Throwable => System.err.println(e)
    }

  } // addWhoisToDb
  private[this] def individualDbUpdate(page: PageInfo, connection: Connection): Unit = {
    val statement: Statement = connection.createStatement()
    statement.setQueryTimeout(30)

    val intValue = ipToLong(page.ip)

    /** Testing conversion of IPv4 to Int */
    println("Testing conversion of IPv4 to Int")

    println(intValue)

    // val ipValue = ipToLong(ip)

    val query = s"SELECT * FROM IPLocData WHERE start_ipint <= $intValue AND end_ipint >= $intValue"

    val result = statement.executeQuery(query)

    var index = 0
    while (result.next()) {
      /** The Index value from geolocation db  */
      index = index + result.getInt("index")
    }

    println("Index = " + index )
    if(index == 0 ) index = 999999999

    var ip = ""
    if(page.ip.nonEmpty) ip = page.ip
    else ip = "None"
    var name = ""

    if(page.name.nonEmpty) name = page.name
    else ip = "None"

    var city = ""
    if(page.city.nonEmpty)
      city = page.city
    else
      city = "None"

    var state = ""
    if(page.state.nonEmpty)
      state = page.state
    else
      state = page.state

    var street = "None"
    if(page.street.nonEmpty)
      street = page.street
    else
      street = "None"

    var country = ""
    if(page.country.nonEmpty)
      country = page.country
    else
      country = "None"

    var post = ""
    if(page.post.nonEmpty)
      post = page.post
    else
      post = "None"
    var url = ""
    if(page.url.nonEmpty)
      url = page.url
    else
      url = "None"

    var description = ""
    if(page.description.nonEmpty)
      description = page.description
    else
      description = "None"

    val timestamp = java.sql.Types.TIMESTAMP

    val splitRange = page.ipRange.split('-')
    val startIpLong = ipToLong(splitRange(0).trim)
    val endIpLong = ipToLong(splitRange(1).trim)

    // val newStatement = connection.createStatement()
    // newStatement.setQueryTimeout(30)
    /*
    val updateStatement = s"INSERT INTO Whois ($index, \'$ip\', \'$name\', \'$city\', \'$state\'," +
      s" \'$street\', \'$country\', \'$post\', $startIpLong, $endIpLong, \'$url\', \'$description\', \'$timestamp\')" +
      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"
      */
    val updateStatement = s"INSERT INTO Whois (index, ip, name, city, state," +
      s" street, country, post, start_ip, end_ip, url, description, date_added)" +
    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"

    val pstmt = connection.prepareStatement(updateStatement)

    // $startIpLong, $endIpLong,
    pstmt.setInt(1, index)
    pstmt.setString(2, ip)
    pstmt.setString(3, name)
    pstmt.setString(4, city)
    pstmt.setString(5, state)
    pstmt.setString(6, street)
    pstmt.setString(7, country)
    pstmt.setString(8, post)
    pstmt.setInt(9, startIpLong.toInt)
    pstmt.setInt(10, endIpLong.toInt)
    pstmt.setString(11, url)
    pstmt.setString(12, description)
    pstmt.setInt(13, timestamp)

   pstmt.executeUpdate(updateStatement)

  } // END individualDbUpdate()

  private[this] def getWhoIs(str: String): PageInfo = {
    val whois = new WhoIs(str)
    val result = Try(whois.query()).getOrElse(PageInfo(str, "Failed", "Failed", "Failed", "", "","","","", ""))

    return result
  }

  def readFile(pcap: String): Try[Vector[String]] = {
    Try(Source.fromFile(pcap).getLines.toVector)
  } // END readFile()

  private[this] def getCommonTargetPort(portNo: String): (String, String) = {

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
    return (portNo, Try(commonTargetPorts(portNo)).getOrElse("None"))
  } // END getCommonTargetPort()

  /** Pass a port number to check risk associated w/ port number */
  private[this] def getPortRisk(portNo: String): (String, String) = {

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

    return (portNo, Try(probPorts(portNo)).getOrElse("None"))
  } // END getProbPort()


} // END AutomatePcapAnalysis
