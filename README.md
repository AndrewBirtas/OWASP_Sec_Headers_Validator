# OWASP Security Headers Validator
A simple script that verifies a server's headers against the recommended security headers from OWASP Secure Headers Project

Usage:
ruby OHV.rb -u "https://example.com"

If there are extra headers to specify, use -c "Cookie:cookie_name=cookie_value"

or 

ruby OHV.rb -r "/path/to/burp_file"
