package com.security.pcap

import java.sql.{Connection, DriverManager, Statement}
import scala.collection.mutable.ArrayBuffer
import scala.util.Try

final case class Geolocation(ip: String,
                             postal_code: String,
                             latitude: String,
                             longitude: String,
                             accuracy_radius: String,
                             appears_continent_name: String ,
                             appears_country_name: String,
                             appears_subdivision_1_name: String,
                             appears_city_name: String,
                             registered_city_name: String,
                             registered_continent_name: String,
                             registered_country_name: String,
                             registered_subdivision_1_name: String,
                             mismatchBool: Boolean
                            ) extends IpInfo(ip) {
  override def toString = {
    s"Geolocation for IP address: $ip\nRegistered Location $registered_country_name $registered_continent_name\n" +
    s"Registered City: $registered_city_name\n" +
    s"Registered Subdivision: $registered_subdivision_1_name\nAppears Country and Continent" +
    s"Name: $appears_country_name $appears_continent_name\nAppears City: $appears_city_name\n" +
    s"Appears Subdivision: $appears_subdivision_1_name\nLatitude: $latitude\nLongitude: $longitude\n" +
    s"Accuracy Radius: $accuracy_radius\nPostal Code: $postal_code\nDo registered and appear match? $mismatchBool"
  } // END toString()
  override def getSuccess: Boolean = if(latitude.isEmpty) false else true
  override def getIp: String = ip
} // END Geolocation case class

object GeolocationInfo extends SearchRange {
  def run(ips: Vector[String], whois: Vector[IpInfo]): Vector[IpInfo] = {

    /** Regex to ensure ip addresses are IPv4 */
      val regex = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}".r

      val assertIPv4 = ips.map(x => regex.findFirstIn(x))

      /** Database only includes IPv4 */
      val removeNonIPv4 = assertIPv4.flatten.distinct

      println("Printing IPv4 addresses for query:\n")
      removeNonIPv4.foreach(println)

    /** Set up SQL driver*/
    val path = "jdbc:sqlite:" + System.getProperty("user.dir") + "/pcaps/Ip2GeoLoc.db"

    val connection: Connection = DriverManager.getConnection(path)
    /** Not necessary */
    // val dm: DatabaseMetaData = connection.getMetaData

    println("Executing query for IP geolocation information...\n\nThis may take a while...")

      val geolocVec: Vector[IpInfo] = for{
        ip <- removeNonIPv4
      } yield mkGeoLocClass(ip, connection)

      geolocVec.foreach(println)

    try{
      if(connection != null)
        connection.close()
    } catch{
      case e: Throwable => System.err.println(e)
    }

    val ipInfoResult: Vector[IpInfo] = geolocVec ++: whois

    /** Filter to only include successful results */
    val filterSuccess = ipInfoResult.filter(x => x.getSuccess)

    val ipsFromIpInfo = ipInfoResult.map(x => x.getIp)

    return geolocVec
  } // END run()


  private[this] def mkGeoLocClass(ip: String, connection: Connection): IpInfo = {

    val statement: Statement = connection.createStatement()
    statement.setQueryTimeout(30)

    val intValue = ipToLong(ip)

    /** Testing conversion of IPv4 to Int */
    println("Testing conversion of IPv4 to Int")

    println(intValue)

    // val ipValue = ipToLong(ip)

    val query = s"SELECT * FROM IPLocData WHERE start_ipint <= $intValue AND end_ipint >= $intValue"

    val result = statement.executeQuery(query)

    var appearsSub2 = ""
    var appearsSub1 = ""
    var regCity = ""
    var latitude = ""
    var longitude = ""
    var accuracy = ""
    var appearsCountry = ""
    var appearsContinent = ""
    var registeredCountry = ""
    var appearsCity = ""
    var regContinent = ""
    var regSub1 = ""
    var postalCode = ""

    while(result.next()){
      /** Need these to handle null values */
      latitude = latitude + result.getString("latitude")
      longitude = longitude + result.getString("longitude")
      accuracy = accuracy + result.getString("accuracy_radius")
      appearsCountry = appearsCountry + result.getString("appears_country_name")
      appearsContinent = appearsContinent + result.getString("appears_continent_name")
      registeredCountry = registeredCountry + result.getString("registered_country_name")
      appearsSub1 = appearsSub1 + result.getString("appears_subdivision_1_name")
      appearsSub2 = appearsSub2 + result.getString("appears_subdivision_2_name")
      appearsCity = appearsCity + result.getString("appears_city_name")
      regCity = regCity + result.getString("registered_city_name")
      regContinent = regContinent + result.getString("registered_continent_name")
      regSub1 = regSub1 + result.getString("registered_subdivision_1_name")
      postalCode = postalCode + result.getString("postal_code")
/*
      if(result.wasNull()){
        appearsSub2 = ""
        appearsSub1 = ""
        regCity = ""
        latitude = ""
        longitude = ""
        accuracy = ""
        appearsCountry = ""
        appearsContinent = ""
        registeredCountry = ""
        appearsCity = ""
        regContinent = ""
        regSub1 = ""
        postalCode = ""
      }
      */
      println(s"Appears Country: $registeredCountry\nRegistered City: $regCity")

    } // END while loop

    /** Check if the registered city and country names are same as appears */
    var mismatchBool = true
    if(appearsCountry.nonEmpty & registeredCountry.nonEmpty){
      if(appearsCountry != registeredCountry) mismatchBool = false
    }
    if(appearsCity.nonEmpty & regCity.nonEmpty){
      if(appearsCity != regCity) mismatchBool = false
    }

    if (appearsSub2.nonEmpty) appearsSub2 =  " or " + appearsSub2

    val geoLoc = {Geolocation(ip, postalCode, latitude, longitude, accuracy, appearsContinent,
      appearsCountry, appearsSub1 + appearsSub2, appearsCity, regCity, regContinent,
      registeredCountry, regSub1, mismatchBool)}

    return geoLoc
  } // END mkGeoLocClass

}// END GeolocationInfo
