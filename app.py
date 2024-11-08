import socket
import ssl
import OpenSSL
import dns.resolver
import streamlit as st
import time

# Function to check SSL certificate information
def check_ssl_cert(domain):
    try:
        # Connect to the server and get the SSL certificate
        conn = ssl.create_connection((domain, 443))
        context = ssl.create_default_context()
        ssock = context.wrap_socket(conn, server_hostname=domain)
        
        # Get the SSL certificate info
        cert = ssock.getpeercert()
        ssl_info = {
            'issuer': cert.get('issuer'),
            'notBefore': cert.get('notBefore'),
            'notAfter': cert.get('notAfter'),
            'cipher': ssock.cipher()
        }
        return ssl_info
    except Exception as e:
        return {"error": str(e)}

# Function to check the grade of SSL certificate
def check_ssl_grade(domain):
    try:
        conn = ssl.create_connection((domain, 443))
        context = ssl.create_default_context()
        ssock = context.wrap_socket(conn, server_hostname=domain)
        cipher_info = ssock.cipher()

        if cipher_info:
            cipher_name = cipher_info[0]
            # Example: Basic grading based on common cipher suites
            if "AES" in cipher_name:
                return "A"
            elif "RC4" in cipher_name:
                return "C"
            else:
                return "B"
        return "No Grade"
    except Exception as e:
        return "Error: " + str(e)

# Function to check DNS record
def check_dns_record(domain, record_type="A", retries=3, delay=2):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 10  # Set a longer timeout (in seconds)
    resolver.lifetime = 15  # Set a longer lifetime (in seconds)
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Use Google's DNS servers for faster resolution

    # Retry mechanism
    for attempt in range(retries):
        try:
            # Try to resolve the DNS record
            resolver.resolve(domain, record_type)
            return "Green"  # Record exists
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return "Red"  # Record missing
        except dns.exception.DNSException as e:
            if attempt < retries - 1:
                time.sleep(delay)  # Wait before retrying
            else:
                return f"Error: {str(e)}"  # Final failure after retries

# Streamlit UI
st.set_page_config(page_title="SSL & DNS Checker", page_icon="🔒")
st.title("SSL & DNS Checker 🔒")

domain = st.text_input("Enter Domain (e.g., example.com):")

# Add the button to trigger the check
if st.button("Check SSL & DNS"):
    if domain:
        # SSL Certificate Info
        ssl_info = check_ssl_cert(domain)
        if "error" in ssl_info:
            st.error(f"SSL Certificate Error: {ssl_info['error']}")
        else:
            st.subheader("SSL Certificate Information:")
            st.write(f"**Issuer:** {ssl_info['issuer']}")
            st.write(f"**Not Before:** {ssl_info['notBefore']}")
            st.write(f"**Not After:** {ssl_info['notAfter']}")
            st.write(f"**Cipher Suite:** {ssl_info['cipher'][0]}")

            # SSL Grade
            ssl_grade = check_ssl_grade(domain)
            st.write(f"**SSL Grade:** {ssl_grade}")

        # DNS Record Check
        st.subheader("DNS Record Check:")
        status = check_dns_record(domain, "A")  # Check for 'A' record by default
        if status == "Green":
            st.success("DNS record found (Green status).")
        elif status == "Red":
            st.error("DNS record missing (Red status).")
        else:
            st.error(f"Error during DNS check: {status}")

        # How to use info
        st.sidebar.markdown("### 💡 How to Use")
        st.sidebar.write("""
        1. **Enter a domain name**: Type the domain you want to check (e.g., example.com).
        2. **Click 'Check SSL & DNS'**: This will trigger the SSL and DNS checks for your domain.
        3. **View SSL certificate info**: You'll see the issuer, validity, and cipher information.
        4. **Check DNS records**: The app will check the DNS record for the domain (Green/Red status).
        """)
    else:
        st.error("Please enter a domain name to check.")
