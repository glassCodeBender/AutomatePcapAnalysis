package com.security.pcap

import sys.process._
import scala.io.Source
import java.util.Calendar

import scala.util.Try

class AutomatePcapAnalysis(pcapFile: String) {

  def run(): Unit = {

    val read = readFile(pcapFile)
    if(read.isFailure) {
      println("Failed to read file...")
      System.exit(1)
    }else{

      val csvVec: Vector[String] = read.get
      val csvContent = csvVec.tail.map(_.split(','))

      
      val ipSrc: Vector[String] = csvContent.map(x => x(7)).distinct 
      val ipDst: Vector[String] = csvContent.map(x => x(8)).distinct

      val udpSrc: Vector[String] = csvContent.map(x => x(12)).distinct
      val udpDst: Vector[String] = csvContent.map(x => x(13)).distinct
      
      val tcpSrc = csvContent.map(x => x(15)).distinct 
      val tcpDest = csvContent.map(x => x(16)).distinct 
     
      /** Need to do checking to see which values use other protocols 
        * 
        * Then perform WhoIs lookup
        */
      
      /**
        * COLUMNS:
        * 0"frame_time",
        * 1"ip_version",
        * 2"ip_id",
        * 3"ip_len",
        * 4"ip_proto",
        * 5"ip_ttl",
        * 6"ip_flags",
        * 7"ip_src",
        * 8"ip_dst",
        * 9"icmp_code",
        * 10"icmp_type",
        * 11"icmp_resptime",
        * 12"udp_srcport",
        * 13"udp_dstport",
        * 14"dns_id",
        * 15"dns_qry_tcp_srcport",
        * 16"tcp_dstport",
        * 17"http_request_method",
        * 18"http_host",
        * 19"http_request_version",
        * 20"http _user_agent",
        * 21"http_server",
        * 22"http_response_code",
        * 23"http_response_phrase"
        */

    }


  } // END main()

  def readFile(pcap: String): Try[Vector[String]] = {
    Try(Source.fromFile(pcap).getLines.toVector)
  } // END readFile()

  def runTshark = {


  }
} // END AutomatePcapAnalysis
