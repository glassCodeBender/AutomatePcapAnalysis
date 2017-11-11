package com.security.pcap

object AnalyzePcapMain {

  def main(args: Array[String]): Unit = {
    // val fileName = "/Users/AlCoolDudeBinRoqui/Documents/pcaps/morningcapture.pcap"

    val pcap = new AutomatePcapAnalysis(args(1))

    pcap.run()



  } // END main()
} // END AnalyzePcapMain object
