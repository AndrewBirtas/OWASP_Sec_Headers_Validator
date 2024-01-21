require 'net/http'
require 'uri'
require 'optparse'
require 'json'

# Function to fetch the list of headers to check from a URL
def fetch_headers_to_check(url)
    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)
  
    if response.is_a?(Net::HTTPSuccess)
      headers_data = JSON.parse(response.body)
  
      headers_to_check = headers_data['headers'].map { |header| header['name'].downcase }
      return headers_to_check
    else
      puts "Error fetching headers data from #{url}"
      return []
    end
  end

#Fetch Headers From URL
def fetch_headers(url, headers={})
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
    puts "Headers fetched from #{url}:\n#{res_headers}"
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
            puts "Headers fetched from #{uri}:\n#{res_headers}"
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
    puts "Content read from Burp request file (#{file_path}):\n#{content}"
    fetch_headers_from_request(file_path)
  rescue StandardError => e
    puts "Error reading Burp request file (#{file_path}): #{e.message}"
  end
end

def check_headers_presence(response_headers)

    headers_to_check = fetch_headers_to_check('https://owasp.org/www-project-secure-headers/ci/headers_add.json')
    headers_to_check.each do |header|
      header_name = header.downcase
      if response_headers.key?(header_name)
        puts "Header '#{header}' is present in the response."
      else
        puts "Header '#{header}' is NOT present in the response."
      end
    end
  end  

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: ruby script.rb [options]"

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
end.parse!

if options[:url]
  fetch_headers(options[:url], options[:headers])
elsif options[:request_file]
  read_burp_request(options[:request_file])
else
  puts "Please specify either a URL (-u) or a Burp request file (-r)."
end