package com.security.pcap

/**
  * Adds geolocation functionality from a database my friend set me up with
  * will be used to look for proxy servers and specific location of IP address.
  */

import scala.collection.parallel.immutable.ParVector
import scala.util.Try

object GeolocationInfo extends SearchRange {
  def run(ips: Vector[String], db: Vector[String]) = {
/*
    /** Since we don't know start and end addresses yet*/
    val startAddr = 1
    val endAddr = 2
*/
    /** Assumes CSV */
    val csv: ParVector[Array[String]] = db.map(x => x.split(',')).par

    /** Hoping to do this with parallel collections. */
    val longIp: ParVector[Long] = ips.map(x => ipToLong(x)).par

  } // END run()

  /** Returns Tuple w/ String IP value, Vector[Array */
  private[this] def getValues(ipVec: ParVector[String], csv: ParVector[Array[String]]):
                                                                    Vector[(String, Array[String])] = {

    val result: ParVector[(String, Array[String])] = for(ip <- ipVec) yield (ip, getIndexInfo(ip, csv))

    result.toVector
  } // END getValues()

  /** Get Index info that matches */
  private[this] def getIndexInfo(ip: String, vec: ParVector[Array[String]]): Array[String] = {
    val longIp = ipToLong(ip)
    val rowValue: ParVector[Array[String]] = for{
      row <- vec
      if row(1).toInt to row(2).toInt contains longIp
    } yield row

    /** At this point it will be a much smaller amount of data. */
    Try(rowValue.head).getOrElse(Array("FAILED", "FAILED", "FAILED", "FAILED", "FAILED", "FAILED", "FAILED", "FAILED"))
  } // END getIndexInfo()


}// END GeolocationInfo
