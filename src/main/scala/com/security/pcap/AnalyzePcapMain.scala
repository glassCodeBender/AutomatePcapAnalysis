package com.security.pcap

object AnalyzePcapMain {

  def main(args: Array[String]): Unit = {

    val csvFile = io.Source.fromFile("Documents/pcaps/file_reads.txt").mkString.trim
    val fileName =  System.getProperty("user.dir") + "/" + csvFile

    val pcap = new AutomatePcapAnalysis(fileName)

    pcap.run()

  } // END main()
} // END AnalyzePcapMain object
