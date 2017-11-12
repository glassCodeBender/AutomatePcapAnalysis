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

      val csvVec: Vector[String] = read.get.drop(1)
      /** Remove headers and create 2d array */
      val csvContent = csvVec.map(_.split(','))

      /** Grab content from various ip address columns */
      val ipSrc: Vector[String] = csvContent.map(x => x(8)).distinct
      val ipDst: Vector[String] = csvContent.map(x => x(9)).distinct

      println("ipSrc size: " + ipSrc.size)
      println("ipDst size: " + ipDst.size)

      println("Printing ipSrc: ")
      ipSrc.foreach(println)
      println("Printing ipDst: ")
      ipDst.foreach(println)

      /** Find the values in src that are not in dst */
      val ipSrcDiff = ipSrc.diff(ipDst)
      println("Print ipSrcDiff")
      ipSrcDiff.foreach(println)
      println("Printing ipSrcDiff count: " + ipSrcDiff.size )

      val ipDstDiff = ipDst.diff(ipSrc)
      println("Print ipDstDiff")
      ipDstDiff.foreach(println)
      println("Printing ipDstDiff count: " + ipDstDiff.size )

      /**
        * NEED TO REMOVE LOCAL IPs
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

  def readFile(pcap: String): Try[Vector[String]] = {
    Try(Source.fromFile(pcap).getLines.toVector)
  } // END readFile()

  def runTshark = {


  }
} // END AutomatePcapAnalysis
