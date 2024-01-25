require 'net/http'
require 'nokogiri'
require 'uri'
require 'open-uri'
require 'optparse'
require 'json'
require 'colorize'
require 'colorized_string'


def display_banner
  banner = <<-'BANNER'
      _    _                _           _    _                _    
     | |  | |              | |         | |  | |              | |   
     | |__| | ___  __ _  __| | ___ _ __| |__| | __ ___      _| | __
     |  __  |/ _ \/ _` |/ _` |/ _ \\'__|  __  |/ _` \ \ /\ / | |/ /
     | |  | |  __| (_| | (_| |  __| |  | |  | | (_| |\ V  V /|   < 
     |_|  |_|\___|\__,_|\__,_|\___|_|  |_|  |_|\__,_| \_/\_/ |_|\_\
                                                                  
  BANNER

  puts banner
  end

# Function to fetch the list of headers to check from a URL
def fetch_headers_to_check(url)
    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)
  
    if response.is_a?(Net::HTTPSuccess)
      headers_data = JSON.parse(response.body)
  
      #headers_to_check = headers_data['headers'].map { |header| header['name'].downcase }
      #return headers_to_check

      headers_to_check = {}
    
      headers_data['headers'].each do |header|
      name = header['name'].downcase
      value = header['value']
      headers_to_check[name] = value
    end
      return headers_to_check
    else
      puts "Error fetching headers data from #{url}"
      return {}
    end
  end

def fetch_headers_deprecated()
  url = 'https://owasp.org/www-project-secure-headers/#div-headers'

  begin
    html = URI.open(url)
    doc = Nokogiri::HTML(html)

    deprecated_section = doc.at('strong:contains("Deprecated")')

    if deprecated_section
      ul_tag = deprecated_section.xpath('following::ul').first

      if ul_tag
        deprecated_headers = ul_tag.css('li a').map do |a_tag|
          header_name = a_tag.text.downcase
          { name: header_name, deprecated: true }
        end

        if deprecated_headers.any?
          return deprecated_headers
        else
          puts "#{'No "Deprecated" headers found on the page'.red}"
        end
      else
        puts "#{'No "Deprecated" section found on the page'.red}"
      end
    else
      puts "#{'No "Deprecated" section found on the page'.red}"
    end
  rescue StandardError => e
    puts "Error fetching or parsing the webpage: #{e.message}"
  end
end

#Fetch Headers From URL
def fetch_headers_from_url(url, headers={})
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == 'https')

  request = Net::HTTP::Get.new(uri.request_uri)

  # Include headers if provided
  headers.each { |header, value| request[header] = value } if headers

  begin
    response = http.request(request)
    #content = response.body
    res_headers = response.to_hash

    #DEBUG LINE#
    #puts "Headers fetched from #{url}:\n#{res_headers}"
    #puts "Body fetched from #{url}:\n#{content}"
    check_headers_presence(res_headers)
  rescue StandardError => e
    puts "Error fetching headers from #{url}: #{e.message}"
  end
end

#Fetch Headers From Burp File
def fetch_headers_from_request(file_path)
    begin
      request_content = File.read(file_path)
      host_match = request_content.match(/Host: (.+?)\r\n/)
      
      if host_match
        host = host_match[1]
        uri = URI.parse("https://#{host}")
        
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == 'https')
  
        request = Net::HTTP::Get.new(uri.request_uri)
        request.body = request_content.split(/\r\n\r\n/, 2).last
  
        # Extract and set cookies and other headers
        request_content.scan(/^(.*?):\s*(.*?)\r\n/).each do |header|
            header_name, header_value = header[0], header[1]
            
            # Exclude certain headers
            unless ['host', 'accept-encoding', 'content-encoding'].include?(header_name.downcase)
              request[header_name] = header_value
            end
          end
  
        begin
            response = http.request(request)
            #content = response.body
            res_headers = response.to_hash

            #DEBUG LINE#
            #puts "Headers fetched from #{uri}:\n#{res_headers}"
            #puts "Body fetched from #{uri}:\n#{content}"
            check_headers_presence(res_headers)
        rescue StandardError => e
            puts "Error fetching headers from #{url}: #{e.message}"
        end
      else
        puts "Error: Host not found in the Burp request file (#{file_path})."
      end
    rescue StandardError => e
      puts "Error fetching headers from the request in #{file_path}: #{e.message}"
    end
  end

# Read Burp File
def read_burp_request(file_path)
  begin
    content = File.read(file_path)
    #DEBUG LINE#
    #puts "Content read from Burp request file (#{file_path}):\n#{content}"
    fetch_headers_from_request(file_path)
  rescue StandardError => e
    puts "Error reading Burp request file (#{file_path}): #{e.message}"
  end
end

def check_headers_presence(response_headers)

    headers_to_check = fetch_headers_to_check('https://owasp.org/www-project-secure-headers/ci/headers_add.json')
    headers_deprecated = fetch_headers_deprecated()

    headers_to_check.each do |header, recommended_value|
      header_name = header.downcase
      
      response_value = response_headers[header_name]

      if header_name == 'pragma'
        puts "=====Acknoledgement====="
        puts "The Pragma Header might be present just for backwards compatability with HTTP1/0"
      end
      # Handle the case where the response value is an array
      response_value = response_value.join(', ') if response_value.is_a?(Array)

      # Strip and lowercase the response value
      response_value = response_value.to_s.strip.downcase
      
      puts "\n\n\n========================================================================\n"
      if response_headers.key?(header_name)
        puts "Header '#{header_name.capitalize.yellow.bold}' #{'is present'.green} in the response."
        if response_value == recommended_value.downcase
          puts "Header '#{header_name.capitalize.yellow.bold}' #{'is present and has the recommended value'.green} in the response."
          #puts "Recommended value is\t #{recommended_value}.\nPresent configuration is\t #{response_value}"
          printf "%-25s %s\n", "Recommended value is:", recommended_value
          printf "%-25s %s\n", "Present configuration is:", response_value
        else
          puts "Header '#{header_name.capitalize.yellow.bold}' #{'is present but does not have the recommended value'.red} in the response."
          #puts "Recommended value is\t #{recommended_value}.\nPresent configuration is\t #{response_value}"
          printf "%-25s %s\n", "Recommended value is:", recommended_value
          printf "%-25s %s\n", "Present configuration is:", response_value
        end
      else
        puts "Header '#{header_name.capitalize.yellow.bold}' #{'is NOT present'.red} in the response."
      end
    end

    puts "\n\n\n============================Deprecated headers============================\n"
    headers_deprecated.each do |deprecate_i|
      header_name = deprecate_i[:name]

      #DEBUG LINE#
      #puts "#{deprecate_i[:name]}"
      if response_headers.key?(header_name)
        puts ColorizedString["HEADER #{header_name.upcase.bold} IS PRESENT."].colorize(:black).bold.on_red.underline
        #puts "#{'HEADER'} '#{header_name.capitalize.purple.bold}' #{'IS PRESENT AND IS DEPRECATED.'.purple} "
        puts "========================================================================\n"
        puts "\nPlease perform further manual checks as well in order to validate the results outputed by this script."
        puts "Happy hacking!"
        puts "©2024 Wh1t3Flag"
      end
    end
  end  


options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: ruby script.rb [options]"
  display_banner

  opts.on("-u", "--url URL", "Specify URL") do |url|
    options[:url] = url
  end

  opts.on("-c", "--cookie NAME=VALUE", "Specify a header") do |header|
    name, value = header.split(':',2)
    options[:headers] ||= {}
    options[:headers][name] = value
  end

  opts.on("-r", "--request FILE", "Specify Burp request file") do |file_path|
    options[:request_file] = file_path
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end

end.parse!

if options[:url]
  fetch_headers_from_url(options[:url], options[:headers])
  #fetch_headers_deprecated()
elsif options[:request_file]
  read_burp_request(options[:request_file])
else
  puts "\nPlease refer to (-h) or --help for instructions."
end