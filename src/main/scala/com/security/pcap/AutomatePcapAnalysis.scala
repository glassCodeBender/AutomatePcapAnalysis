package com.security.pcap
// import sys.process._
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

      /** Filter out local IP addresses */
      val filterOutLocal = concatIp.filterNot(_.startsWith("192"))
        .filterNot(_.startsWith("10"))
        .filterNot(_.startsWith("172"))

      val distinctIps: Vector[String] = filterOutLocal.distinct

      // val regex = "\"".r
      // val cleanIps = distinctIps.map(x => regex.replaceAllIn(x, ""))

      /** Removing quotes because the regex won't work! */
      val clean = distinctIps.map(_.drop(1))
      val cleanerIps = clean.map(_.dropRight(1))

      val pageInfoFound: Vector[PageInfo] = whoIsQuery(cleanerIps)

      // Send results to json 
      
      println("Printing Page Info Found")

      pageInfoFound.foreach(println)

      /**
        * grab common values and put in data structure.
        * grab distinct values and put in two other data structures.
        */

        // THESE ARE GRABBING PORT NUMBERS
      val udpSrc: Vector[String] = csvContent.map(x => x(13)).distinct
      val udpDst: Vector[String] = csvContent.map(x => x(14)).distinct

      val udpSrcDiff = udpSrc.diff(udpDst)
      println("Print udpSrcDiff")
      udpSrcDiff.foreach(println)

      val udpDstDiff = udpDst.diff(udpSrc)
      println("Print udpDstDiff")
      udpDstDiff.foreach(println)

      /**
        * grab common values and put in data structure.
        * grab distinct values and put in two other data structures.
        */

      // Skipping port numbers for now

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
    val result = Try(whois.query()).getOrElse(PageInfo("Failed", "Failed", "Failed", "Failed", "", "","","",""))

    return result
  }

  def readFile(pcap: String): Try[Vector[String]] = {
    Try(Source.fromFile(pcap).getLines.toVector)
  } // END readFile()

  def runTshark = {


  }
} // END AutomatePcapAnalysis
